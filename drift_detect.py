#!/usr/bin/env python3
"""
infra-drift-detector CLI

Usage:
  drift-detect scan --profile prod --region eu-west-1
  drift-detect scan --profile prod --region eu-west-1 --state terraform.tfstate --remediate
  drift-detect scan --profile prod --region eu-west-1 --output report.html --format html
"""

import argparse
import json
import sys
import logging
from pathlib import Path

from src.drift_engine import DriftEngine
from src.reporters.html_reporter import HTMLReporter, JSONReporter
from src.notifiers.sns import SNSNotifier

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Detect infrastructure drift between Terraform state and live AWS resources"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run a drift scan")
    scan.add_argument("--profile",    default=None,   help="AWS profile name (default: standard credential chain, e.g. OIDC in CI)")
    scan.add_argument("--region",     default="eu-west-1", help="AWS region")
    scan.add_argument("--state",      default=None,   help="Path to terraform.tfstate")
    scan.add_argument("--output",     default=None,   help="Output file path (default: stdout)")
    scan.add_argument("--format",     choices=["json","html"], default="json")
    scan.add_argument("--remediate",  action="store_true",     help="Auto-remediate safe findings")
    scan.add_argument("--sns-topic",  default=None,   help="SNS topic ARN for critical alerts")
    scan.add_argument("--fail-on-critical", action="store_true",
                      help="Exit with code 1 if critical findings exist (for CI use)")
    scan.add_argument("--verbose",    action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    engine = DriftEngine(
        profile=args.profile,
        region=args.region,
        state_path=args.state,
    )

    report = engine.scan(auto_remediate=args.remediate)

    # Generate report
    if args.format == "html":
        output = HTMLReporter().generate(report)
    else:
        output = JSONReporter().generate(report)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Summary to stderr so it doesn't pollute piped output
    print(
        f"\nSummary: {len(report.findings)} findings | "
        f"{report.critical_count} critical | "
        f"{report.warning_count} warning | "
        f"{report.info_count} info | "
        f"{report.remediated_count} remediated",
        file=sys.stderr
    )

    # SNS alerts for critical findings
    if args.sns_topic and report.critical_count > 0:
        notifier = SNSNotifier(profile=args.profile, region=args.region, topic_arn=args.sns_topic)
        notifier.alert(report)

    if args.fail_on_critical and report.critical_count > 0:
        log.error(f"Exiting with code 1 — {report.critical_count} critical finding(s)")
        sys.exit(1)


if __name__ == "__main__":
    main()
