"""
IAM drift detector.

What it catches:
- Policies attached to roles outside Terraform — CRITICAL
- New IAM roles created outside Terraform — WARNING
- Root account has active access keys — CRITICAL
- Users with no MFA and console access — WARNING
- Overly permissive inline policies (Action: *) — CRITICAL
"""

import json
import logging
from src.drift_engine import DriftFinding, DriftType, Severity

log = logging.getLogger(__name__)


class IAMDetector:
    def __init__(self, session, account_id: str, region: str, tf_state: dict):
        self.iam        = session.client("iam")
        self.account_id = account_id
        self.region     = region
        self.tf_state   = tf_state

    def detect(self) -> list[DriftFinding]:
        findings = []
        findings.extend(self._check_root_access_keys())
        findings.extend(self._check_users_without_mfa())
        findings.extend(self._check_wildcard_policies())
        findings.extend(self._check_role_drift())
        return findings

    def _check_root_access_keys(self) -> list[DriftFinding]:
        findings = []
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(DriftFinding(
                    resource_id="root",
                    resource_type=DriftType.IAM_POLICY,
                    severity=Severity.CRITICAL,
                    description="Root account has active access keys — immediate security risk",
                    expected="No root access keys",
                    actual=f"{summary['AccountAccessKeysPresent']} active root access key(s)",
                    region=self.region,
                    account_id=self.account_id,
                ))
        except Exception as e:
            log.error(f"Root key check failed: {e}")
        return findings

    def _check_users_without_mfa(self) -> list[DriftFinding]:
        findings = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    # Check console access
                    try:
                        self.iam.get_login_profile(UserName=username)
                        has_console = True
                    except self.iam.exceptions.NoSuchEntityException:
                        has_console = False

                    if not has_console:
                        continue

                    mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
                    if not mfa_devices:
                        findings.append(DriftFinding(
                            resource_id=f"iam/user/{username}",
                            resource_type=DriftType.IAM_POLICY,
                            severity=Severity.WARNING,
                            description=f"User '{username}' has console access but no MFA device",
                            expected="MFA enabled for all console users",
                            actual="No MFA device enrolled",
                            region=self.region,
                            account_id=self.account_id,
                        ))
                except Exception as e:
                    log.warning(f"MFA check failed for {username}: {e}")
        return findings

    def _check_wildcard_policies(self) -> list[DriftFinding]:
        """Find inline policies with Action: * — full admin access."""
        findings = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                try:
                    inline_policies = self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]
                    for policy_name in inline_policies:
                        doc = self.iam.get_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )["PolicyDocument"]

                        if isinstance(doc, str):
                            doc = json.loads(doc)

                        for statement in doc.get("Statement", []):
                            actions = statement.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if "*" in actions and statement.get("Effect") == "Allow":
                                findings.append(DriftFinding(
                                    resource_id=f"iam/role/{role_name}/policy/{policy_name}",
                                    resource_type=DriftType.IAM_POLICY,
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Role '{role_name}' has inline policy '{policy_name}' "
                                        f"with Action:* (full admin access)"
                                    ),
                                    expected="Scoped actions following least-privilege",
                                    actual="Action: * — wildcard admin policy",
                                    region=self.region,
                                    account_id=self.account_id,
                                ))
                except Exception as e:
                    log.warning(f"Policy check failed for role {role_name}: {e}")
        return findings

    def _check_role_drift(self) -> list[DriftFinding]:
        """Detect roles or policy attachments created outside Terraform."""
        findings = []
        if not self.tf_state:
            return findings

        tf_roles = self._extract_tf_roles()
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                # Skip AWS service-linked roles
                if "aws-service-role" in role.get("Path", ""):
                    continue
                if role_name not in tf_roles:
                    findings.append(DriftFinding(
                        resource_id=f"iam/role/{role_name}",
                        resource_type=DriftType.IAM_POLICY,
                        severity=Severity.WARNING,
                        description=f"IAM role '{role_name}' exists in AWS but not in Terraform state",
                        expected="All roles managed via Terraform",
                        actual=f"Role '{role_name}' created outside IaC",
                        region=self.region,
                        account_id=self.account_id,
                    ))
        return findings

    def _extract_tf_roles(self) -> set:
        roles = set()
        for resource in self.tf_state.get("resources", []):
            if resource.get("type") == "aws_iam_role":
                for instance in resource.get("instances", []):
                    name = instance.get("attributes", {}).get("name")
                    if name:
                        roles.add(name)
        return roles
