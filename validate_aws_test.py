"""
Validation test for the Cloud Security Audit tool.

Runs main.py on test_aws_environment.json (FICTIONAL AWS-style data, no real AWS
account), reads the generated JSON report, and checks that:
  - every intentionally insecure setting is detected (FAIL), and
  - every correctly configured item passes its checks (PASS).
The summary is built only from the actual report, then printed and saved.

Run:  python validate_aws_test.py
"""

import json
import os
import re
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = "test_aws_environment.json"
REPORT_NAME = "aws_environment_test_report.json"
SUMMARY_FILE = os.path.join(BASE_DIR, "reports", "aws_validation_summary.md")

# (description, check name starts with, target starts with, expected status)
EXPECTED = [
    ("data_analyst has MFA disabled", "MFA is enabled", "data_analyst", "FAIL"),
    ("data_analyst role has wildcard permissions", "No wildcard", "DataAnalystRole", "FAIL"),
    ("customer-raw-data is public", "Bucket is not publicly accessible", "customer-raw-data", "FAIL"),
    ("customer-raw-data not encrypted at rest", "Encryption at rest", "customer-raw-data", "FAIL"),
    ("customer-raw-data not encrypted in transit", "Encryption in transit", "customer-raw-data", "FAIL"),
    ("ETL pipeline not encrypted in transit", "Encryption in transit", "customer-etl-job", "FAIL"),
    ("Cloud audit logging disabled", "CTL-06", "Logging", "FAIL"),
    ("etl_service role is least-privilege", "No wildcard", "EtlServiceRole", "PASS"),
    ("processed-data public access blocked", "Bucket is not publicly accessible", "processed-data", "PASS"),
    ("processed-data encrypted at rest", "Encryption at rest", "processed-data", "PASS"),
    ("processed-data encrypted in transit", "Encryption in transit", "processed-data", "PASS"),
    ("Redshift encrypted at rest", "Encryption at rest", "sales-dw", "PASS"),
    ("Redshift encrypted in transit", "Encryption in transit", "sales-dw", "PASS"),
]


def main():
    # 1. Run the real audit program
    run = subprocess.run([sys.executable, os.path.join(BASE_DIR, "main.py"),
                          INPUT_FILE, REPORT_NAME],
                         cwd=BASE_DIR, capture_output=True, text=True)
    if run.returncode != 0:
        print("Audit program failed:\n", run.stdout, run.stderr)
        sys.exit(1)

    # 2. Find the report path the program actually wrote
    match = re.search(r"JSON report saved to: (.+)", run.stdout)
    report_path = match.group(1).strip()
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    checks = report["all_checks"]

    # 3. Compare expected vs actual
    rows, all_ok = [], True
    for desc, check, target, expected in EXPECTED:
        hits = [c for c in checks if c["check"].startswith(check) and c["target"].startswith(target)]
        actual = hits[0]["status"] if hits else "NOT CHECKED"
        sev = hits[0]["severity"] if hits else ""
        ok = actual == expected
        all_ok = all_ok and ok
        rows.append((desc, expected, actual + (f" ({sev})" if sev else ""), "YES" if ok else "NO"))

    # The service account must NOT get an MFA check
    svc_mfa = [c for c in checks if c["check"] == "MFA is enabled" and c["target"] == "etl_service"]
    rows.append(("etl_service: MFA check skipped (service account)", "SKIPPED",
                 "SKIPPED" if not svc_mfa else svc_mfa[0]["status"], "YES" if not svc_mfa else "NO"))
    all_ok = all_ok and not svc_mfa

    s = report["summary"]
    result = "PASSED - all expected results matched" if all_ok else "FAILED - see rows marked NO"

    # 4. Print and save the summary
    lines = ["# Validation Summary: AWS-style Test Environment", "",
             "Fictional AWS-style data audited by main.py. This is NOT a real AWS security scan.", "",
             f"Command: `python main.py {INPUT_FILE} {REPORT_NAME}`", f"Report: `{report_path}`", "",
             "| Expected item | Expected | Actual | Matched |", "|---|---|---|---|"]
    lines += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in rows]
    lines += ["",
              f"Total checks: {s['total_checks']} | Passed: {s['passed']} | Failed: {s['failed']} "
              f"(HIGH {s['high_risk']}, MEDIUM {s['medium_risk']}, LOW {s['low_risk']})",
              f"Overall status reported: {s['overall_status']}", "",
              f"**Validation result: {result}**"]
    text = "\n".join(lines)
    print(text)
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"\nValidation summary saved to: {SUMMARY_FILE}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
