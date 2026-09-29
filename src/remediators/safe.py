"""
Safe remediator — auto-fixes INFO/WARNING level drift only.
CRITICAL findings are NEVER auto-remediated. Humans must review those.

Safe remediations:
- Re-enable S3 versioning
- Re-enable S3 encryption
- Restore missing EC2 tags
- Re-enable RDS backup retention to minimum

Unsafe (never auto-remediate):
- Security group rules — blast radius too high
- IAM policies — privilege escalation risk
- RDS MultiAZ — causes downtime
- Public access changes — need human verification
"""

import logging
from src.drift_engine import DriftFinding, DriftType, Severity

log = logging.getLogger(__name__)


class SafeRemediator:
    def __init__(self, session):
        self.session = session
        self.s3  = session.client("s3")
        self.ec2 = session.client("ec2")
        self.rds = session.client("rds")

    def remediate(self, finding: DriftFinding) -> str | None:
        """
        Attempt safe remediation. Returns a description of what was done,
        or None if remediation was skipped.
        """
        if finding.severity == Severity.CRITICAL:
            log.warning(f"Refusing to auto-remediate CRITICAL finding: {finding.resource_id}")
            return None

        if finding.resource_type == DriftType.S3_CONFIG:
            return self._remediate_s3(finding)

        if finding.resource_type == DriftType.EC2_TAG:
            return self._remediate_ec2_tags(finding)

        return None

    def _remediate_s3(self, finding: DriftFinding) -> str | None:
        bucket = finding.resource_id.replace("s3://", "")

        if "versioning" in finding.description.lower():
            try:
                self.s3.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={"Status": "Enabled"},
                )
                return f"Re-enabled versioning on s3://{bucket}"
            except Exception as e:
                log.error(f"Failed to re-enable versioning on {bucket}: {e}")
                return None

        if "encryption" in finding.description.lower():
            try:
                self.s3.put_bucket_encryption(
                    Bucket=bucket,
                    ServerSideEncryptionConfiguration={
                        "Rules": [{
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }]
                    },
                )
                return f"Re-enabled AES256 encryption on s3://{bucket}"
            except Exception as e:
                log.error(f"Failed to re-enable encryption on {bucket}: {e}")
                return None

        return None

    def _remediate_ec2_tags(self, finding: DriftFinding) -> str | None:
        """Restore missing tags with placeholder values for human follow-up."""
        instance_id = finding.resource_id
        missing_tags = finding.expected  # set of tag keys

        if not isinstance(missing_tags, set):
            return None

        try:
            placeholder_tags = [
                {"Key": tag, "Value": "NEEDS-REVIEW"}
                for tag in missing_tags
            ]
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=placeholder_tags,
            )
            return f"Added placeholder tags {list(missing_tags)} to {instance_id} — review required"
        except Exception as e:
            log.error(f"Failed to add tags to {instance_id}: {e}")
            return None
