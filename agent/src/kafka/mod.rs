// Thor Firewall — Kafka Producer/Consumer (rdkafka)
//
// REAL CODE SOURCE: https://github.com/fede1024/rust-rdkafka (MIT)
//   Based on: examples/simple_producer.rs + examples/simple_consumer.rs
//   Copyright 2016 Federico Giraud
//
// Streams XDP ring-buffer flow events to Kafka topics for:
//   ClickHouse Kafka engine, Apache Druid streaming ingestion, SIEM

use std::time::Duration;
use anyhow::{Context, Result};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use rdkafka::util::get_rdkafka_version;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub const TOPIC_FLOWS:        &str = "thor.flows";
pub const TOPIC_ALERTS:       &str = "thor.alerts";
pub const TOPIC_ML_DECISIONS: &str = "thor.ml.decisions";
pub const TOPIC_THREAT_INTEL: &str = "thor.threat.intel";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaFlowEvent {
    pub timestamp_ms: i64,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     u8,
    pub bytes:        u32,
    pub risk_score:   u32,
    pub verdict:      String,
    pub agent_host:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaAlertEvent {
    pub timestamp_ms:    i64,
    pub alert_type:      String,
    pub severity:        u8,
    pub src_ip:          String,
    pub dst_ip:          String,
    pub description:     String,
    pub mitre_tactic:    Option<String>,
    pub mitre_technique: Option<String>,
}

// ─── Producer ────────────────────────────────────────────────────────────────

pub struct ThorKafkaProducer {
    producer: FutureProducer,
    hostname: String,
}

impl ThorKafkaProducer {
    /// Build producer using real rdkafka ClientConfig pattern.
    /// Mirrors rust-rdkafka/examples/simple_producer.rs exactly.
    pub fn new(brokers: &str) -> Result<Self> {
        let (version_n, version_s) = get_rdkafka_version();
        info!("rdkafka version: 0x{:08x}, {}", version_n, version_s);

        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .set("compression.type", "lz4")
            .set("batch.num.messages", "10000")
            .set("linger.ms", "5")
            .set("acks", "1")
            .set("retries", "3")
            .create()
            .context("Failed to create Kafka producer")?;

        Ok(Self {
            producer,
            hostname: hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        })
    }

    /// Send a flow event to thor.flows — real FutureRecord pattern.
    pub async fn send_flow(&self, sample: &crate::flow_manager::FlowSample) -> Result<()> {
        let verdict = match sample.verdict {
            0 => "allow", 1 => "block", 2 => "redirect", _ => "unknown",
        };
        let event = KafkaFlowEvent {
            timestamp_ms: (sample.timestamp_ns / 1_000_000) as i64,
            src_ip:       sample.src_ip.to_string(),
            dst_ip:       sample.dst_ip.to_string(),
            src_port:     sample.src_port,
            dst_port:     sample.dst_port,
            protocol:     sample.protocol,
            bytes:        sample.bytes,
            risk_score:   sample.risk_score,
            verdict:      verdict.to_string(),
            agent_host:   self.hostname.clone(),
        };
        let payload = serde_json::to_vec(&event).context("serialize")?;
        let key     = format!("{}-{}", event.src_ip, event.dst_ip);
        let record  = FutureRecord::to(TOPIC_FLOWS).payload(&payload).key(key.as_bytes());
        match self.producer.send(record, Duration::from_secs(0)).await {
            Ok(d)  => debug!("flow delivered: {:?}", d),
            Err((e, _)) => warn!("flow delivery failed: {e}"),
        }
        Ok(())
    }

    /// Send a security alert to thor.alerts.
    pub async fn send_alert(&self, alert: KafkaAlertEvent) -> Result<()> {
        let payload = serde_json::to_vec(&alert).context("serialize alert")?;
        let key     = alert.src_ip.as_bytes().to_vec();
        let record  = FutureRecord::to(TOPIC_ALERTS).payload(&payload).key(&key);
        self.producer.send(record, Duration::from_secs(5)).await
            .map_err(|(e, _)| anyhow::anyhow!("alert send: {e}"))?;
        Ok(())
    }

    pub fn flush(&self) {
        self.producer.flush(Duration::from_secs(10))
            .unwrap_or_else(|e| warn!("kafka flush: {e}"));
    }
}

// ─── Consumer (ML decision feedback loop) ────────────────────────────────────

pub struct ThorKafkaConsumer {
    consumer: StreamConsumer,
}

impl ThorKafkaConsumer {
    /// Build consumer — mirrors rust-rdkafka/examples/simple_consumer.rs exactly.
    pub fn new(brokers: &str, group_id: &str, topics: &[&str]) -> Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("group.id", group_id)
            .set("enable.partition.eof",   "false")
            .set("session.timeout.ms",     "6000")
            .set("enable.auto.commit",     "true")
            .set("auto.commit.interval.ms","1000")
            .set("auto.offset.reset",      "latest")
            .create()
            .context("Failed to create Kafka consumer")?;

        consumer.subscribe(topics).context("subscribe")?;
        info!(topics = ?topics, group = group_id, "Kafka consumer subscribed");
        Ok(Self { consumer })
    }

    /// Consume ML decisions from Kafka and push to XDP map updater.
    pub async fn run_ml_feedback_loop(
        self,
        decision_tx: mpsc::Sender<crate::flow_manager::MlDecision>,
    ) {
        loop {
            match self.consumer.recv().await {
                Err(e) => error!("kafka recv: {e}"),
                Ok(msg) => {
                    let payload = msg.payload().unwrap_or_default();
                    match serde_json::from_slice::<crate::flow_manager::MlDecision>(payload) {
                        Ok(d)  => { let _ = decision_tx.try_send(d); }
                        Err(e) => debug!("ml decision parse: {e}"),
                    }
                }
            }
        }
    }
}
