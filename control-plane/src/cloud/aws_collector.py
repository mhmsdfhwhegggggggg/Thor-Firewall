"""
AWS Security Collector — CloudTrail + GuardDuty + Security Hub + Config
Real-time and batch collection of AWS security telemetry
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncGenerator

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger("thor.cloud.aws")

# MITRE mappings for AWS CloudTrail events
_CLOUDTRAIL_MITRE = {
    "ConsoleLogin":                  ["T1078.004"],  # Cloud Accounts
    "AssumeRoleWithWebIdentity":     ["T1550.001"],  # Use Alternate Auth Material
    "CreateUser":                    ["T1136.003"],  # Create Cloud Account
    "AttachUserPolicy":              ["T1098.003"],  # Add Office 365 Global Admin Role
    "CreateAccessKey":               ["T1098"],      # Account Manipulation
    "PutBucketPolicy":               ["T1530"],      # Data from Cloud Storage Object
    "GetSecretValue":                ["T1552.001"],  # Credentials in Files
    "DescribeInstances":             ["T1580"],      # Cloud Infrastructure Discovery
    "RunInstances":                  ["T1578.002"],  # Create Cloud Instance
    "ModifyInstanceAttribute":       ["T1578"],      # Modify Cloud Compute Infrastructure
    "CreateSecurityGroup":           ["T1562.007"],  # Disable or Modify Cloud Firewall
    "AuthorizeSecurityGroupIngress": ["T1562.007"],
    "DeleteCloudTrail":              ["T1562.008"],  # Disable Cloud Logs
    "StopLogging":                   ["T1562.008"],
    "PutEventSelectors":             ["T1562.008"],
    "CreateLoginProfile":            ["T1136"],      # Create Account
    "UpdateLoginProfile":            ["T1098"],
    "DeleteLogGroup":                ["T1562"],      # Impair Defenses
}

class AWSCollector:
    """
    AWS multi-service security collector.
    Collects CloudTrail, GuardDuty findings, and Security Hub findings.
    Supports cross-account collection via assumed roles.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        role_arn: str | None = None,
        sqs_queue_url: str | None = None,
        s3_bucket: str | None = None,
        lookback_hours: int = 1,
    ):
        self.region         = region
        self.role_arn       = role_arn
        self.sqs_queue_url  = sqs_queue_url
        self.s3_bucket      = s3_bucket
        self.lookback_hours = lookback_hours
        self._session       = None

    def _get_session(self) -> boto3.Session:
        if self._session:
            return self._session

        if self.role_arn:
            sts = boto3.client("sts", region_name=self.region)
            creds = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="ThorFirewallCollector",
                DurationSeconds=3600,
            )["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id     = creds["AccessKeyId"],
                aws_secret_access_key = creds["SecretAccessKey"],
                aws_session_token     = creds["SessionToken"],
                region_name           = self.region,
            )
        else:
            self._session = boto3.Session(region_name=self.region)

        return self._session

    # ─────────────────────────── CloudTrail ────────────────────────────

    async def collect_cloudtrail(
        self, lookback_hours: int | None = None
    ) -> AsyncGenerator[dict, None]:
        """
        Collect CloudTrail events via LookupEvents API.
        For high-volume production: use SQS → S3 notification pipeline instead.
        """
        hours = lookback_hours or self.lookback_hours
        session = self._get_session()
        client = session.client("cloudtrail", region_name=self.region)

        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        paginator = client.get_paginator("lookup_events")

        logger.info("Collecting CloudTrail events %s → %s", start_time.isoformat(), end_time.isoformat())

        loop = asyncio.get_event_loop()
        try:
            pages = await loop.run_in_executor(
                None,
                lambda: list(paginator.paginate(
                    StartTime=start_time,
                    EndTime=end_time,
                    PaginationConfig={"MaxItems": 10000, "PageSize": 50},
                ))
            )
        except (ClientError, NoCredentialsError) as e:
            logger.error("CloudTrail collection failed: %s", e)
            return

        for page in pages:
            for raw_event in page.get("Events", []):
                yield self._normalize_cloudtrail(raw_event)

    def _normalize_cloudtrail(self, raw: dict) -> dict:
        """Normalize CloudTrail event to Thor canonical format"""
        ct = raw.get("CloudTrailEvent", "{}")
        if isinstance(ct, str):
            try:
                ct = json.loads(ct)
            except Exception:
                ct = {}

        event_name      = raw.get("EventName", ct.get("eventName", ""))
        event_time      = raw.get("EventTime", ct.get("eventTime"))
        source_ip       = ct.get("sourceIPAddress", "")
        user_agent      = ct.get("userAgent", "")
        error_code      = ct.get("errorCode", "")
        error_msg       = ct.get("errorMessage", "")
        aws_region      = ct.get("awsRegion", self.region)
        request_params  = ct.get("requestParameters") or {}
        response_params = ct.get("responseElements") or {}

        # Extract principal
        user_identity = ct.get("userIdentity", {})
        principal     = (
            user_identity.get("userName") or
            user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or
            user_identity.get("principalId", "").split(":")[-1] or
            user_identity.get("type", "unknown")
        )
        account_id = user_identity.get("accountId", "")

        ts_ms = 0
        if event_time:
            if isinstance(event_time, datetime):
                ts_ms = int(event_time.timestamp() * 1000)
            else:
                try:
                    dt = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
                    ts_ms = int(dt.timestamp() * 1000)
                except Exception:
                    ts_ms = int(time.time() * 1000)

        risk_score = self._score_cloudtrail(event_name, error_code, user_identity)
        mitre = _CLOUDTRAIL_MITRE.get(event_name, [])

        return {
            "id":               raw.get("EventId", ""),
            "timestamp_ms":     ts_ms,
            "source_format":    "cloudtrail",
            "source_host":      f"aws:{aws_region}",
            "source_ip":        source_ip,
            "category":         "cloud",
            "action":           event_name,
            "outcome":          "failure" if error_code else "success",
            "actor_user":       principal,
            "target_resource":  raw.get("Resources", [{}])[0].get("ResourceName", "") if raw.get("Resources") else "",
            "mitre_techniques": mitre,
            "risk_score":       risk_score,
            "raw":              json.dumps(raw),
            "labels": {
                "cloud_provider":   "aws",
                "aws_region":       aws_region,
                "account_id":       account_id,
                "event_source":     ct.get("eventSource", ""),
                "user_agent":       user_agent,
                "error_code":       error_code,
                "error_message":    error_msg,
                "mfa_authenticated": str(
                    user_identity.get("sessionContext", {})
                        .get("attributes", {})
                        .get("mfaAuthenticated", "false")
                ).lower(),
            },
        }

    def _score_cloudtrail(
        self, event_name: str, error_code: str, user_identity: dict
    ) -> float:
        score = 0.0

        # Known high-risk events
        high_risk = {
            "DeleteCloudTrail", "StopLogging", "PutEventSelectors",
            "DeleteLogGroup", "DeleteTrail", "CreateUser", "AttachUserPolicy",
            "CreateAccessKey", "GetSecretValue", "AssumeRoleWithWebIdentity",
        }
        medium_risk = {
            "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
            "PutBucketPolicy", "DeleteBucketPolicy", "RunInstances",
            "ModifyInstanceAttribute", "UpdateLoginProfile",
        }

        if event_name in high_risk:    score += 0.7
        elif event_name in medium_risk: score += 0.4

        # Repeated failures → brute force
        if error_code in ("AccessDenied", "UnauthorizedOperation"): score += 0.2

        # Root account usage
        if user_identity.get("type") == "Root": score += 0.4

        # No MFA for console login
        if event_name == "ConsoleLogin":
            mfa = user_identity.get("sessionContext", {}).get("attributes", {}).get("mfaAuthenticated", "false")
            if mfa.lower() == "false": score += 0.3

        return min(score, 1.0)

    # ─────────────────────────── GuardDuty ─────────────────────────────

    async def collect_guardduty(self) -> AsyncGenerator[dict, None]:
        """Collect active GuardDuty findings"""
        session = self._get_session()
        client = session.client("guardduty", region_name=self.region)

        loop = asyncio.get_event_loop()

        try:
            detectors = await loop.run_in_executor(
                None, lambda: client.list_detectors()
            )
        except (ClientError, NoCredentialsError) as e:
            logger.error("GuardDuty list_detectors failed: %s", e)
            return

        for detector_id in detectors.get("DetectorIds", []):
            paginator = client.get_paginator("list_findings")
            try:
                pages = await loop.run_in_executor(
                    None,
                    lambda: list(paginator.paginate(
                        DetectorId=detector_id,
                        FindingCriteria={
                            "Criterion": {
                                "severity": {"Gte": 4},  # medium and above
                                "service.archived": {"Eq": ["false"]},
                            }
                        }
                    ))
                )
            except ClientError as e:
                logger.error("GuardDuty list_findings failed: %s", e)
                continue

            all_ids = [fid for page in pages for fid in page.get("FindingIds", [])]

            # Batch get findings (max 50 per call)
            for i in range(0, len(all_ids), 50):
                batch = all_ids[i:i+50]
                try:
                    findings = await loop.run_in_executor(
                        None,
                        lambda b=batch: client.get_findings(DetectorId=detector_id, FindingIds=b)
                    )
                    for finding in findings.get("Findings", []):
                        yield self._normalize_guardduty(finding)
                except ClientError as e:
                    logger.error("GuardDuty get_findings error: %s", e)

    def _normalize_guardduty(self, finding: dict) -> dict:
        svc = finding.get("Service", {})
        action = svc.get("Action", {})
        severity = finding.get("Severity", 0)

        resource = finding.get("Resource", {})
        instance = resource.get("InstanceDetails", {})
        access_key = resource.get("AccessKeyDetails", {})

        actor_user = (
            access_key.get("UserName") or
            access_key.get("PrincipalId", "").split(":")[-1] or ""
        )

        source_ip = ""
        action_type = action.get("ActionType", "")
        if action_type == "NETWORK_CONNECTION":
            nc = action.get("NetworkConnectionAction", {})
            source_ip = nc.get("RemoteIpDetails", {}).get("IpAddressV4", "")
        elif action_type == "AWS_API_CALL":
            source_ip = action.get("AwsApiCallAction", {}).get("RemoteIpDetails", {}).get("IpAddressV4", "")

        risk_score = min(severity / 10.0, 1.0)
        log_level = "CRITICAL" if severity >= 7 else "HIGH" if severity >= 4 else "MEDIUM"

        return {
            "id":               finding.get("Id", ""),
            "timestamp_ms":     int(
                datetime.fromisoformat(
                    finding.get("UpdatedAt", finding.get("CreatedAt", "1970-01-01T00:00:00Z"))
                    .replace("Z", "+00:00")
                ).timestamp() * 1000
            ),
            "source_format":    "guardduty",
            "source_host":      f"aws:{finding.get('Region', self.region)}",
            "source_ip":        source_ip,
            "category":         "cloud",
            "action":           finding.get("Type", "").replace("/", "_"),
            "outcome":          "detected",
            "actor_user":       actor_user,
            "log_level":        log_level,
            "risk_score":       risk_score,
            "mitre_techniques": [],  # GuardDuty maps to MITRE natively in newer API
            "raw":              json.dumps(finding),
            "labels": {
                "cloud_provider": "aws",
                "finding_type":   finding.get("Type", ""),
                "title":          finding.get("Title", ""),
                "description":    finding.get("Description", "")[:500],
                "detector_id":    finding.get("DetectorId", ""),
                "severity":       str(severity),
                "account_id":     finding.get("AccountId", ""),
                "resource_type":  resource.get("ResourceType", ""),
                "instance_id":    instance.get("InstanceId", ""),
            },
        }

    # ─────────────────────────── SQS Stream ────────────────────────────

    async def stream_from_sqs(self) -> AsyncGenerator[dict, None]:
        """
        Production-grade SQS consumer for high-volume CloudTrail → S3 → SNS → SQS pipeline.
        Processes S3 notification messages, downloads log files from S3, parses them.
        """
        if not self.sqs_queue_url:
            logger.error("SQS queue URL not configured")
            return

        session = self._get_session()
        sqs = session.client("sqs", region_name=self.region)
        s3  = session.client("s3",  region_name=self.region)
        loop = asyncio.get_event_loop()

        logger.info("Starting SQS stream from: %s", self.sqs_queue_url)

        while True:
            try:
                resp = await loop.run_in_executor(
                    None,
                    lambda: sqs.receive_message(
                        QueueUrl=self.sqs_queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=20,  # long-polling
                        AttributeNames=["All"],
                    )
                )
            except ClientError as e:
                logger.error("SQS receive error: %s", e)
                await asyncio.sleep(5)
                continue

            for msg in resp.get("Messages", []):
                try:
                    body = json.loads(msg["Body"])
                    # SNS → SQS wrapping
                    if "Message" in body:
                        body = json.loads(body["Message"])

                    for record in body.get("Records", []):
                        s3_info = record.get("s3", {})
                        bucket  = s3_info.get("bucket", {}).get("name", "")
                        key     = s3_info.get("object", {}).get("key", "")

                        if bucket and key:
                            async for event in self._download_and_parse_s3(s3, bucket, key):
                                yield event

                    # Delete processed message
                    await loop.run_in_executor(
                        None,
                        lambda: sqs.delete_message(
                            QueueUrl=self.sqs_queue_url,
                            ReceiptHandle=msg["ReceiptHandle"]
                        )
                    )
                except Exception as e:
                    logger.error("SQS message processing error: %s", e)

    async def _download_and_parse_s3(
        self, s3, bucket: str, key: str
    ) -> AsyncGenerator[dict, None]:
        import gzip
        import io

        loop = asyncio.get_event_loop()
        try:
            obj = await loop.run_in_executor(
                None, lambda: s3.get_object(Bucket=bucket, Key=key)
            )
            body = obj["Body"].read()
            # CloudTrail logs are gzip-compressed
            if key.endswith(".gz"):
                body = gzip.decompress(body)

            data = json.loads(body)
            for record in data.get("Records", []):
                yield self._normalize_cloudtrail({"CloudTrailEvent": json.dumps(record), **record})

        except Exception as e:
            logger.error("S3 download error s3://%s/%s: %s", bucket, key, e)
