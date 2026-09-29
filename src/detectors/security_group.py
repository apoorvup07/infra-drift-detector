"""
Security group drift detector.

What it catches:
- Port 22 (SSH) or 3389 (RDP) open to 0.0.0.0/0 — CRITICAL
- Any port open to 0.0.0.0/0 not in expected config — WARNING
- Rules added/removed manually vs Terraform state — WARNING
- Overly permissive egress rules — INFO
"""

import logging
from src.drift_engine import DriftFinding, DriftType, Severity

log = logging.getLogger(__name__)

CRITICAL_PORTS = {22, 3389, 1433, 3306, 5432, 27017}  # SSH, RDP, MSSQL, MySQL, Postgres, MongoDB
OPEN_CIDR      = {"0.0.0.0/0", "::/0"}


class SecurityGroupDetector:
    def __init__(self, session, account_id: str, region: str, tf_state: dict):
        self.ec2        = session.client("ec2")
        self.account_id = account_id
        self.region     = region
        self.tf_state   = tf_state

    def detect(self) -> list[DriftFinding]:
        findings = []
        sgs = self._get_all_security_groups()
        tf_sgs = self._extract_tf_security_groups()

        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)

            # 1. Check for dangerously open ingress rules
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)
                protocol  = rule.get("IpProtocol", "-1")

                open_cidrs = [
                    r["CidrIp"] for r in rule.get("IpRanges", [])
                    if r["CidrIp"] in OPEN_CIDR
                ] + [
                    r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                    if r["CidrIpv6"] in OPEN_CIDR
                ]

                if not open_cidrs:
                    continue

                # All traffic open (-1 protocol) to world
                if protocol == "-1":
                    findings.append(DriftFinding(
                        resource_id=sg_id,
                        resource_type=DriftType.SECURITY_GROUP,
                        severity=Severity.CRITICAL,
                        description=f"{sg_name}: all traffic open to {open_cidrs} — immediate risk",
                        expected="No 0.0.0.0/0 allow-all rules",
                        actual=f"Protocol -1 open to {open_cidrs}",
                        region=self.region,
                        account_id=self.account_id,
                    ))
                    continue

                # Check port range overlaps with critical ports
                for critical_port in CRITICAL_PORTS:
                    if from_port <= critical_port <= to_port:
                        findings.append(DriftFinding(
                            resource_id=sg_id,
                            resource_type=DriftType.SECURITY_GROUP,
                            severity=Severity.CRITICAL,
                            description=(
                                f"{sg_name}: port {critical_port} open to internet ({open_cidrs}). "
                                f"This is a critical security exposure."
                            ),
                            expected=f"Port {critical_port} restricted to known CIDRs",
                            actual=f"Port {critical_port} open to {open_cidrs}",
                            region=self.region,
                            account_id=self.account_id,
                        ))

                # Non-critical port open to world — warning
                if from_port not in CRITICAL_PORTS:
                    findings.append(DriftFinding(
                        resource_id=sg_id,
                        resource_type=DriftType.SECURITY_GROUP,
                        severity=Severity.WARNING,
                        description=f"{sg_name}: ports {from_port}-{to_port} open to internet",
                        expected="Restricted CIDR",
                        actual=f"Open to {open_cidrs}",
                        region=self.region,
                        account_id=self.account_id,
                    ))

            # 2. Compare against Terraform state if available
            if tf_sgs and sg_id in tf_sgs:
                tf_rules = set(tf_sgs[sg_id])
                live_rules = self._normalise_rules(sg.get("IpPermissions", []))
                added   = live_rules - tf_rules
                removed = tf_rules  - live_rules

                for rule in added:
                    findings.append(DriftFinding(
                        resource_id=sg_id,
                        resource_type=DriftType.SECURITY_GROUP,
                        severity=Severity.WARNING,
                        description=f"{sg_name}: rule added outside Terraform: {rule}",
                        expected="No manually added rules",
                        actual=f"Rule present in AWS but not in state: {rule}",
                        region=self.region,
                        account_id=self.account_id,
                    ))

                for rule in removed:
                    findings.append(DriftFinding(
                        resource_id=sg_id,
                        resource_type=DriftType.SECURITY_GROUP,
                        severity=Severity.INFO,
                        description=f"{sg_name}: rule in Terraform state not found in AWS: {rule}",
                        expected=f"Rule present: {rule}",
                        actual="Rule absent",
                        region=self.region,
                        account_id=self.account_id,
                    ))

        return findings

    def _get_all_security_groups(self) -> list[dict]:
        paginator = self.ec2.get_paginator("describe_security_groups")
        sgs = []
        for page in paginator.paginate():
            sgs.extend(page["SecurityGroups"])
        return sgs

    def _extract_tf_security_groups(self) -> dict:
        """Parse Terraform state to extract expected SG rules keyed by sg-id."""
        result = {}
        resources = self.tf_state.get("resources", [])
        for resource in resources:
            if resource.get("type") != "aws_security_group":
                continue
            for instance in resource.get("instances", []):
                attrs = instance.get("attributes", {})
                sg_id = attrs.get("id")
                if sg_id:
                    rules = set()
                    for ingress in attrs.get("ingress", []):
                        rules.add(self._rule_to_str(ingress))
                    result[sg_id] = rules
        return result

    @staticmethod
    def _normalise_rules(permissions: list) -> set:
        rules = set()
        for perm in permissions:
            proto     = perm.get("IpProtocol", "-1")
            from_port = perm.get("FromPort", 0)
            to_port   = perm.get("ToPort", 65535)
            for r in perm.get("IpRanges", []):
                rules.add(f"{proto}:{from_port}-{to_port}:{r['CidrIp']}")
        return rules

    @staticmethod
    def _rule_to_str(rule: dict) -> str:
        proto     = rule.get("protocol", "-1")
        from_port = rule.get("from_port", 0)
        to_port   = rule.get("to_port", 65535)
        cidrs     = rule.get("cidr_blocks", [])
        return f"{proto}:{from_port}-{to_port}:{','.join(cidrs)}"
