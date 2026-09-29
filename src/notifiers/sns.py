"""
SNS notifier — sends critical drift alerts via SNS → email/SMS/PagerDuty
"""
import json
import logging
import boto3
from src.drift_engine import DriftReport, Severity

log = logging.getLogger(__name__)


class SNSNotifier:
    def __init__(self, profile: str, region: str, topic_arn: str):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.sns       = session.client("sns")
        self.topic_arn = topic_arn

    def alert(self, report: DriftReport):
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        if not critical:
            return

        subject = f"[CRITICAL] {len(critical)} infrastructure drift finding(s) — {report.account_id} / {report.region}"

        lines = [f"Infrastructure drift detected at {report.scanned_at}\n"]
        lines.append(f"Account: {report.account_id}  Region: {report.region}\n")
        lines.append(f"Critical findings: {len(critical)}\n")
        lines.append("-" * 60)
        for f in critical:
            lines.append(f"\n[CRITICAL] {f.resource_id}")
            lines.append(f"  Type: {f.resource_type.value}")
            lines.append(f"  {f.description}")
            lines.append(f"  Expected: {f.expected}")
            lines.append(f"  Actual:   {f.actual}")

        lines.append(f"\n\nFull report: check CloudWatch Logs or S3 report bucket.")
        message = "\n".join(lines)

        try:
            self.sns.publish(
                TopicArn=self.topic_arn,
                Subject=subject,
                Message=message,
            )
            log.info(f"SNS alert sent to {self.topic_arn}")
        except Exception as e:
            log.error(f"SNS publish failed: {e}")
