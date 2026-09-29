# infra-drift-detector

[![CI](https://github.com/apoorvup07/infra-drift-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/apoorvup07/infra-drift-detector/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Detects when live AWS infrastructure has drifted from its Terraform state or expected security baseline. Runs as a CLI or an on-demand GitHub Actions workflow (OIDC, no stored keys). Auto-remediates safe findings. Alerts via SNS for critical drift.

Built from 9 years of production experience watching infrastructure silently drift after console changes during incidents — and the compliance headaches that followed.

---

## What it detects

| Check | Severity | Auto-remediate |
|---|---|---|
| Port 22/3389 open to 0.0.0.0/0 | 🔴 Critical | ❌ Never |
| IAM roles with inline `Action: *` policies | 🔴 Critical | ❌ Never |
| Root account active access keys | 🔴 Critical | ❌ Never |
| RDS publicly accessible | 🔴 Critical | ❌ Never |
| S3 public access block disabled | 🔴 Critical | ❌ Never |
| Security group rules added outside Terraform | 🟡 Warning | ❌ Never |
| IAM roles created outside Terraform | 🟡 Warning | ❌ Never |
| Users without MFA (console access) | 🟡 Warning | ❌ Never |
| RDS not Multi-AZ | 🟡 Warning | ❌ Never |
| S3 versioning disabled | 🟡 Warning | ✅ Safe |
| S3 encryption missing | 🟡 Warning | ✅ Safe |
| EC2 instances missing required tags | 🔵 Info | ✅ Safe |

**Critical findings are never auto-remediated** — the blast radius is too high. They alert immediately and require human review.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  CLI / GitHub Actions                       │
└────────────────┬────────────────────────────┘
                 │
         ┌───────▼────────┐
         │  DriftEngine   │  orchestrates all detectors
         └───────┬────────┘
                 │
    ┌────────────┼────────────┬────────────┬────────────┐
    ▼            ▼            ▼            ▼            ▼
 SG Detector  IAM Detector  S3 Detector  RDS Detector  EC2 Tags
    │            │            │
    └────────────┴────────────┴──► DriftReport
                                       │
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                     JSON Report  HTML Report  SNS Alert
```

---

## Quick start

```bash
git clone https://github.com/apoorvup07/infra-drift-detector.git
cd infra-drift-detector
pip install -r requirements.txt

# Basic scan
python drift_detect.py scan --profile prod --region eu-west-1

# With Terraform state comparison
python drift_detect.py scan --profile prod --region eu-west-1 --state terraform.tfstate

# HTML report output
python drift_detect.py scan --profile prod --region eu-west-1 --output report.html --format html

# Auto-remediate safe findings + alert on critical via SNS
python drift_detect.py scan \
  --profile prod \
  --region eu-west-1 \
  --state terraform.tfstate \
  --remediate \
  --sns-topic arn:aws:sns:eu-west-1:123456789:drift-alerts

# CI mode — exits with code 1 on critical findings (blocks pipeline)
python drift_detect.py scan --profile prod --region eu-west-1 --fail-on-critical
```

---

## Sample output

```json
{
  "account_id": "123456789012",
  "region": "eu-west-1",
  "scanned_at": "2025-09-15T08:32:11Z",
  "summary": {
    "total": 7,
    "critical": 2,
    "warning": 3,
    "info": 2,
    "remediated": 2
  },
  "findings": [
    {
      "resource_id": "sg-0abc123def456",
      "resource_type": "security_group",
      "severity": "critical",
      "description": "prod-app-sg: port 22 open to internet (['0.0.0.0/0']). Critical security exposure.",
      "expected": "Port 22 restricted to known CIDRs",
      "actual": "Port 22 open to ['0.0.0.0/0']",
      "remediated": false
    }
  ]
}
```

---

## Testing

All detectors are tested end-to-end against a mocked AWS account with [moto](https://github.com/getmoto/moto), so CI needs no AWS credentials:

```bash
pip install -r requirements-dev.txt
pytest -q
```

Writing these tests surfaced a real bug: the S3 detector referenced boto3 exception classes that don't exist for those error codes, so one missing configuration crashed the whole S3 check. It now matches on the `ClientError` error code instead.

---

## GitHub Actions

- `ci.yml` runs lint and the moto test suite on every push and pull request.
- `drift-scan.yml` runs a real scan **on demand**. It only runs when the `AWS_DRIFT_ROLE_ARN` repository variable is set, and authenticates with GitHub OIDC (no long-lived access keys). Reports are uploaded as build artifacts.

Read-only IAM permissions the scan role needs: `ec2:Describe*`, `iam:List*`, `iam:Get*`, `s3:GetBucket*`, `s3:ListAllMyBuckets`, `rds:Describe*`, `sts:GetCallerIdentity` (plus `sns:Publish` for alerts, and `s3:PutBucketVersioning` / `s3:PutEncryptionConfiguration` / `ec2:CreateTags` only if `--remediate` is used).

---

## Roadmap

- Package as a Lambda + EventBridge schedule
- EKS node group drift checks
- Terraform-state comparison for more resource types

---

## Requirements

- Python 3.11+
- AWS credentials with the read-only permissions listed above
- boto3

## Licence

MIT
