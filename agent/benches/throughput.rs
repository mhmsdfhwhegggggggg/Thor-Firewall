// Thor Firewall — Throughput Benchmarks
// قياس أداء العميل بشكل شامل
//
// الاستخدام:
//   cargo bench -p thor-agent

use criterion::{
    black_box, criterion_group, criterion_main,
    BenchmarkId, Criterion, Throughput,
};

use thor_agent::packet_parser::{PacketParser, RawPacket, ParserConfig};
use thor_agent::flow_manager::{FlowManager, FlowConfig};

// ============================================================================
// Helper: توليد حزم اختبار
// ============================================================================

fn make_raw_packet(i: u32) -> RawPacket {
    RawPacket {
        timestamp_ns: 1_000_000_000 + i as u64 * 1000,
        src_ip: 0xC0A80100 | (i % 65536),       // 192.168.1.x
        dst_ip: 0x0A000001,                        // 10.0.0.1
        sport:  32768 + (i % 32767) as u16,
        dport:  443,
        proto:  6,                                  // TCP
        tcp_flags: 0x10,                            // ACK
        pkt_len: 800 + (i % 700) as u16,
        payload: {
            let mut p = vec![0u8; 64];
            for j in 0..64 { p[j] = ((i + j as u32) % 256) as u8; }
            p
        },
    }
}

// ============================================================================
// PacketParser Benchmarks
// ============================================================================

fn bench_packet_parser(c: &mut Criterion) {
    let parser = PacketParser::new(ParserConfig::default()).unwrap();
    let packet = make_raw_packet(42);

    let mut group = c.benchmark_group("packet_parser");
    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_single_ipv4_tcp", |b| {
        b.iter(|| parser.parse(black_box(&packet)))
    });

    // دفعة من 64 حزمة
    let packets: Vec<RawPacket> = (0..64).map(make_raw_packet).collect();
    group.throughput(Throughput::Elements(64));

    group.bench_function("parse_batch_64", |b| {
        b.iter(|| {
            for pkt in black_box(&packets) {
                let _ = parser.parse(pkt);
            }
        })
    });

    group.finish();
}

// ============================================================================
// FlowManager Benchmarks
// ============================================================================

fn bench_flow_manager(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let fm = FlowManager::new(FlowConfig::default()).unwrap();
    let parser = PacketParser::new(ParserConfig::default()).unwrap();

    let mut group = c.benchmark_group("flow_manager");

    // إدخال تدفق جديد
    group.throughput(Throughput::Elements(1));
    group.bench_function("update_new_flow", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            let pkt = make_raw_packet(counter);
            counter = counter.wrapping_add(1);
            if let Ok((features, meta)) = parser.parse(&pkt) {
                let _ = fm.update(black_box(&meta), black_box(&features));
            }
        })
    });

    // تحديث تدفق موجود (المسار الساخن)
    // تسجيل 1000 تدفق أولاً
    for i in 0..1000 {
        let pkt = make_raw_packet(i);
        if let Ok((features, meta)) = parser.parse(&pkt) {
            fm.update(&meta, &features);
        }
    }

    // قياس التحديث على تدفق موجود
    let hot_packet = make_raw_packet(500);
    if let Ok((features, meta)) = parser.parse(&hot_packet) {
        group.bench_function("update_existing_flow", |b| {
            b.iter(|| fm.update(black_box(&meta), black_box(&features)))
        });
    }

    group.finish();
}

// ============================================================================
// Throughput Test: كم حزمة يمكن معالجتها في الثانية
// ============================================================================

fn bench_end_to_end_throughput(c: &mut Criterion) {
    let parser = PacketParser::new(ParserConfig::default()).unwrap();
    let fm     = FlowManager::new(FlowConfig::default()).unwrap();

    let mut group = c.benchmark_group("e2e_throughput");

    for batch_size in [1, 64, 256, 1024, 4096] {
        let packets: Vec<RawPacket> = (0..batch_size as u32).map(make_raw_packet).collect();
        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &packets,
            |b, pkts| {
                b.iter(|| {
                    for pkt in black_box(pkts) {
                        if let Ok((features, meta)) = parser.parse(pkt) {
                            let _ = fm.update(&meta, &features);
                        }
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Memory Benchmark: حجم الذاكرة لـ 1M تدفق
// ============================================================================

fn bench_flow_table_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("flow_table_memory");
    group.sample_size(10);

    group.bench_function("insert_1M_flows", |b| {
        b.iter(|| {
            let fm = FlowManager::new(FlowConfig {
                max_flows: 1_000_000,
                ..Default::default()
            }).unwrap();
            let parser = PacketParser::new(ParserConfig::default()).unwrap();

            for i in 0..1_000_000u32 {
                let pkt = make_raw_packet(i);
                if let Ok((features, meta)) = parser.parse(&pkt) {
                    fm.update(&meta, &features);
                }
            }
            black_box(fm.stats().active_flows)
        })
    });

    group.finish();
}

// ============================================================================

criterion_group!(
    benches,
    bench_packet_parser,
    bench_flow_manager,
    bench_end_to_end_throughput,
);

// تشغيل المعيار الثقيل فقط مع --features heavy-bench
#[cfg(feature = "heavy-bench")]
criterion_group!(
    heavy_benches,
    bench_flow_table_memory,
);

criterion_main!(benches);
