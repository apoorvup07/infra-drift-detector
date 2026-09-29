"""
S3 drift detector — catches public access, versioning off, policy changes
"""

import logging
from src.drift_engine import DriftFinding, DriftType, Severity

log = logging.getLogger(__name__)


class S3Detector:
    def __init__(self, session, account_id: str, region: str, tf_state: dict):
        self.s3         = session.client("s3")
        self.account_id = account_id
        self.region     = region
        self.tf_state   = tf_state

    def detect(self) -> list[DriftFinding]:
        findings = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except Exception as e:
            log.error(f"S3 list_buckets failed: {e}")
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            findings.extend(self._check_public_access(name))
            findings.extend(self._check_versioning(name))
            findings.extend(self._check_encryption(name))
        return findings

    def _check_public_access(self, name: str) -> list[DriftFinding]:
        findings = []
        try:
            config = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not blocked:
                findings.append(DriftFinding(
                    resource_id=f"s3://{name}",
                    resource_type=DriftType.S3_CONFIG,
                    severity=Severity.CRITICAL,
                    description=f"Bucket '{name}' has public access block disabled",
                    expected="All 4 public access block settings enabled",
                    actual=str(config),
                    region=self.region,
                    account_id=self.account_id,
                ))
        except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append(DriftFinding(
                resource_id=f"s3://{name}",
                resource_type=DriftType.S3_CONFIG,
                severity=Severity.CRITICAL,
                description=f"Bucket '{name}' has no public access block configuration at all",
                expected="Public access block enabled",
                actual="No public access block configuration",
                region=self.region,
                account_id=self.account_id,
            ))
        except Exception as e:
            log.warning(f"Public access check failed for {name}: {e}")
        return findings

    def _check_versioning(self, name: str) -> list[DriftFinding]:
        findings = []
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                findings.append(DriftFinding(
                    resource_id=f"s3://{name}",
                    resource_type=DriftType.S3_CONFIG,
                    severity=Severity.WARNING,
                    description=f"Bucket '{name}' versioning is '{status}' — may have been disabled manually",
                    expected="Versioning: Enabled",
                    actual=f"Versioning: {status}",
                    region=self.region,
                    account_id=self.account_id,
                ))
        except Exception as e:
            log.warning(f"Versioning check failed for {name}: {e}")
        return findings

    def _check_encryption(self, name: str) -> list[DriftFinding]:
        findings = []
        try:
            self.s3.get_bucket_encryption(Bucket=name)
        except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            findings.append(DriftFinding(
                resource_id=f"s3://{name}",
                resource_type=DriftType.S3_CONFIG,
                severity=Severity.WARNING,
                description=f"Bucket '{name}' has no server-side encryption configured",
                expected="SSE-AES256 or SSE-KMS",
                actual="No encryption configuration",
                region=self.region,
                account_id=self.account_id,
            ))
        except Exception as e:
            log.warning(f"Encryption check failed for {name}: {e}")
        return findings


class RDSDetector:
    def __init__(self, session, account_id: str, region: str, tf_state: dict):
        self.rds        = session.client("rds")
        self.account_id = account_id
        self.region     = region
        self.tf_state   = tf_state

    def detect(self) -> list[DriftFinding]:
        findings = []
        try:
            paginator = self.rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    findings.extend(self._check_instance(db))
        except Exception as e:
            log.error(f"RDS describe_db_instances failed: {e}")
        return findings

    def _check_instance(self, db: dict) -> list[DriftFinding]:
        findings = []
        db_id = db["DBInstanceIdentifier"]

        if db.get("PubliclyAccessible", False):
            findings.append(DriftFinding(
                resource_id=f"rds/{db_id}",
                resource_type=DriftType.RDS_CONFIG,
                severity=Severity.CRITICAL,
                description=f"RDS instance '{db_id}' is publicly accessible",
                expected="PubliclyAccessible: false",
                actual="PubliclyAccessible: true",
                region=self.region,
                account_id=self.account_id,
            ))

        if not db.get("MultiAZ", False):
            findings.append(DriftFinding(
                resource_id=f"rds/{db_id}",
                resource_type=DriftType.RDS_CONFIG,
                severity=Severity.WARNING,
                description=f"RDS instance '{db_id}' is not Multi-AZ — may have been changed manually",
                expected="MultiAZ: true",
                actual="MultiAZ: false",
                region=self.region,
                account_id=self.account_id,
            ))

        backup_retention = db.get("BackupRetentionPeriod", 0)
        if backup_retention < 7:
            findings.append(DriftFinding(
                resource_id=f"rds/{db_id}",
                resource_type=DriftType.RDS_CONFIG,
                severity=Severity.WARNING,
                description=f"RDS '{db_id}' backup retention is {backup_retention} days (expected ≥7)",
                expected="BackupRetentionPeriod >= 7",
                actual=f"BackupRetentionPeriod: {backup_retention}",
                region=self.region,
                account_id=self.account_id,
            ))

        if not db.get("StorageEncrypted", False):
            findings.append(DriftFinding(
                resource_id=f"rds/{db_id}",
                resource_type=DriftType.RDS_CONFIG,
                severity=Severity.CRITICAL,
                description=f"RDS instance '{db_id}' storage is not encrypted",
                expected="StorageEncrypted: true",
                actual="StorageEncrypted: false",
                region=self.region,
                account_id=self.account_id,
            ))

        return findings


class EC2TagDetector:
    REQUIRED_TAGS = {"Environment", "Owner", "ManagedBy"}

    def __init__(self, session, account_id: str, region: str, tf_state: dict):
        self.ec2        = session.client("ec2")
        self.account_id = account_id
        self.region     = region
        self.tf_state   = tf_state

    def detect(self) -> list[DriftFinding]:
        findings = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "terminated":
                        continue
                    findings.extend(self._check_tags(instance))
        return findings

    def _check_tags(self, instance: dict) -> list[DriftFinding]:
        findings = []
        instance_id = instance["InstanceId"]
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        missing = self.REQUIRED_TAGS - set(tags.keys())

        if missing:
            findings.append(DriftFinding(
                resource_id=instance_id,
                resource_type=DriftType.EC2_TAG,
                severity=Severity.INFO,
                description=f"Instance {instance_id} missing required tags: {missing}",
                expected=f"Tags: {self.REQUIRED_TAGS}",
                actual=f"Present tags: {set(tags.keys())}",
                region=self.region,
                account_id=self.account_id,
            ))
        return findings
