"""
infra-drift-detector — core drift detection engine
Compares live AWS infrastructure state against Terraform state + expected config.
Supports: security groups, IAM, S3, RDS, EC2, EKS node groups
"""

import json
import logging
import boto3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"   # Auto-alert + block. Never auto-remediate.
    WARNING  = "warning"    # Alert only
    INFO     = "info"       # Report only


class DriftType(str, Enum):
    SECURITY_GROUP  = "security_group"
    IAM_POLICY      = "iam_policy"
    S3_CONFIG       = "s3_config"
    RDS_CONFIG      = "rds_config"
    EC2_TAG         = "ec2_tag"
    EKS_NODE_GROUP  = "eks_node_group"


@dataclass
class DriftFinding:
    resource_id:    str
    resource_type:  DriftType
    severity:       Severity
    description:    str
    expected:       Any
    actual:         Any
    region:         str
    account_id:     str
    remediated:     bool = False
    remediation_note: str = ""
    detected_at:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["resource_type"] = self.resource_type.value
        d["severity"]      = self.severity.value
        return d


class DriftEngine:
    """
    Orchestrates all detectors and aggregates findings.
    Usage:
        engine = DriftEngine(profile="prod", region="eu-west-1", state_path="terraform.tfstate")
        report = engine.scan()
    """

    def __init__(self, profile: str, region: str, state_path: str | None = None,
                 expected_config_path: str | None = None):
        self.profile  = profile
        self.region   = region
        self.session  = boto3.Session(profile_name=profile, region_name=region)
        self.sts      = self.session.client("sts")
        self.account_id = self.sts.get_caller_identity()["Account"]

        self.tf_state       = self._load_json(state_path)        if state_path        else {}
        self.expected_config = self._load_json(expected_config_path) if expected_config_path else {}

        self.findings: list[DriftFinding] = []

        # Import detectors lazily to keep engine testable in isolation
        from src.detectors.security_group import SecurityGroupDetector
        from src.detectors.iam            import IAMDetector
        from src.detectors.s3             import S3Detector
        from src.detectors.rds            import RDSDetector
        from src.detectors.ec2            import EC2TagDetector

        self.detectors = [
            SecurityGroupDetector(self.session, self.account_id, self.region, self.tf_state),
            IAMDetector(self.session, self.account_id, self.region, self.tf_state),
            S3Detector(self.session, self.account_id, self.region, self.tf_state),
            RDSDetector(self.session, self.account_id, self.region, self.tf_state),
            EC2TagDetector(self.session, self.account_id, self.region, self.tf_state),
        ]

    def scan(self, auto_remediate: bool = False) -> "DriftReport":
        log.info(f"Starting drift scan | account={self.account_id} region={self.region}")

        for detector in self.detectors:
            log.info(f"Running detector: {detector.__class__.__name__}")
            try:
                findings = detector.detect()
                self.findings.extend(findings)
                log.info(f"  → {len(findings)} finding(s)")
            except Exception as e:
                log.error(f"  ✗ Detector failed: {e}")

        if auto_remediate:
            self._remediate()

        report = DriftReport(
            account_id=self.account_id,
            region=self.region,
            profile=self.profile,
            findings=self.findings,
        )
        log.info(f"Scan complete | critical={report.critical_count} warning={report.warning_count} info={report.info_count}")
        return report

    def _remediate(self):
        from src.remediators.safe import SafeRemediator
        remediator = SafeRemediator(self.session)
        for finding in self.findings:
            if finding.severity == Severity.CRITICAL:
                log.warning(f"Skipping auto-remediation for CRITICAL finding: {finding.resource_id}")
                continue
            try:
                result = remediator.remediate(finding)
                if result:
                    finding.remediated = True
                    finding.remediation_note = result
                    log.info(f"Remediated: {finding.resource_id} — {result}")
            except Exception as e:
                log.error(f"Remediation failed for {finding.resource_id}: {e}")

    @staticmethod
    def _load_json(path: str) -> dict:
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load {path}: {e}")
            return {}


@dataclass
class DriftReport:
    account_id: str
    region:     str
    profile:    str
    findings:   list[DriftFinding]
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def remediated_count(self) -> int:
        return sum(1 for f in self.findings if f.remediated)

    def to_dict(self) -> dict:
        return {
            "account_id":       self.account_id,
            "region":           self.region,
            "profile":          self.profile,
            "scanned_at":       self.scanned_at,
            "summary": {
                "total":      len(self.findings),
                "critical":   self.critical_count,
                "warning":    self.warning_count,
                "info":       self.info_count,
                "remediated": self.remediated_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
