"""End-to-end detector tests against a mocked AWS account (moto) — no real AWS calls."""
import json

import boto3
import pytest
from moto import mock_aws

from src.drift_engine import DriftEngine, Severity
from src.reporters.html_reporter import HTMLReporter, JSONReporter

REGION = "eu-west-1"


@pytest.fixture
def aws(monkeypatch, tmp_path):
    creds = tmp_path / "credentials"
    creds.write_text("[test]\naws_access_key_id = testing\naws_secret_access_key = testing\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    with mock_aws():
        yield boto3.Session(profile_name="test", region_name=REGION)


def _scan(remediate=False):
    return DriftEngine(profile="test", region=REGION).scan(auto_remediate=remediate)


def test_open_ssh_is_critical_and_never_remediated(aws):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="t", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    report = _scan(remediate=True)
    hits = [f for f in report.findings if f.resource_id == sg]
    assert hits and hits[0].severity == Severity.CRITICAL
    assert not hits[0].remediated


def test_insecure_bucket_findings_and_safe_remediation(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="demo-bucket", CreateBucketConfiguration={"LocationConstraint": REGION})
    report = _scan(remediate=True)
    bucket = [f for f in report.findings if f.resource_id == "s3://demo-bucket"]
    severities = {f.severity for f in bucket}
    assert Severity.CRITICAL in severities          # no public access block
    assert any(f.remediated for f in bucket)        # versioning/encryption fixed
    assert s3.get_bucket_versioning(Bucket="demo-bucket").get("Status") == "Enabled"


def test_wildcard_inline_role_policy_is_critical(aws):
    iam = aws.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
             "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="too-powerful", AssumeRolePolicyDocument=json.dumps(trust))
    iam.put_role_policy(RoleName="too-powerful", PolicyName="admin", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    report = _scan()
    assert any("too-powerful" in f.resource_id and f.severity == Severity.CRITICAL
               for f in report.findings)


def test_reports_render(aws):
    report = _scan()
    assert json.loads(JSONReporter().generate(report))["region"] == REGION
    assert "<html" in HTMLReporter().generate(report).lower()
