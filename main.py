"""
Cloud Security Audit Tool (Educational Project)
------------------------------------------------
Audits a SIMULATED cloud data engineering environment described in a JSON file.
It checks:
  1. Access control (IAM users and roles)
  2. Encryption (storage, data warehouse, data pipeline)
  3. Compliance (a simplified checklist inspired by ISO 27001, CIS benchmarks
     and cloud security best practices)

NOTE: This is a simplified educational assessment. It does NOT connect to a
real cloud account and does NOT certify compliance with any standard.

Run:  python main.py
      python main.py my_environment.json   (optional: audit another file)
      python main.py my_environment.json my_report.json   (optional report name)
"""

import json
import os
import sys
from datetime import datetime

# Folder of this script, so the program works from any current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(BASE_DIR, "sample_environment.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Every check result is stored in this list
results = []


def add_result(category, check, target, passed, severity="", issue="", remediation=""):
    """Record the result of one audit check."""
    results.append({
        "category": category,
        "check": check,
        "target": target,
        "status": "PASS" if passed else "FAIL",
        "severity": "" if passed else severity,
        "issue": "" if passed else issue,
        "remediation": "" if passed else remediation,
    })


def load_environment(path):
    """Read the cloud configuration JSON file."""
    if not os.path.exists(path):
        print(f"ERROR: Input file not found: {path}")
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {path}: {e}")
        sys.exit(1)


def role_has_wildcard(role):
    """True if a role allows ALL actions ('*' or 'service:*') or ALL resources ('*').
    A scoped path such as 'storage/bucket/*' is NOT treated as a wildcard."""
    for perm in role["permissions"]:
        for action in perm["actions"]:
            if action == "*" or action.endswith(":*"):
                return True
        if "*" in perm["resources"]:
            return True
    return False


# ---------------------------------------------------------------------------
# 1. ACCESS CONTROL AUDIT
# ---------------------------------------------------------------------------
def audit_access_control(env):
    category = "Access Control"
    audit_day = datetime.strptime(env["audit_date"], "%Y-%m-%d").date()
    inactive_limit = env.get("inactive_days_limit", 90)

    for user in env["iam_users"]:
        name = user["username"]

        # Check 1: administrator privileges must be approved
        approved = (not user["is_admin"]) or user["approved_admin"]
        add_result(category, "Admin privileges are approved", name, approved,
                   "HIGH",
                   "User has administrator privileges without approval.",
                   "Remove admin rights or get formal approval; use least-privilege roles.")

        # Check 2: MFA for all enabled human users (HIGH for admins, MEDIUM for others).
        # Service accounts (programs) cannot use MFA, so the check is skipped for them;
        # their safety comes from least-privilege roles instead.
        if user["enabled"] and not user.get("is_service_account", False):
            add_result(category, "MFA is enabled", name, user["mfa_enabled"],
                       "HIGH" if user["is_admin"] else "MEDIUM",
                       "Active account does not use multi-factor authentication.",
                       "Enforce MFA for this user (mandatory for privileged users).")

        # Check 3: inactive accounts must be disabled
        last_login = datetime.strptime(user["last_login"], "%Y-%m-%d").date()
        days_inactive = (audit_day - last_login).days
        stale_and_enabled = user["enabled"] and days_inactive > inactive_limit
        add_result(category, f"No enabled account inactive > {inactive_limit} days", name,
                   not stale_and_enabled, "MEDIUM",
                   f"Account is enabled but unused for {days_inactive} days.",
                   "Disable or remove the account; run periodic access reviews.")

    for role in env["iam_roles"]:
        # Check 4: no wildcard permissions (except an approved break-glass admin role)
        passed = (not role_has_wildcard(role)) or role.get("break_glass_admin_role", False)
        # Show which users hold the role, so the finding points to real accounts
        holders = [u["username"] for u in env["iam_users"] if u["role"] == role["role_name"]]
        target = role["role_name"] + (f" (used by: {', '.join(holders)})" if holders else "")
        add_result(category, "No wildcard (*) permissions", target, passed,
                   "HIGH",
                   "Role grants wildcard actions or resources (overly permissive).",
                   "Replace '*' with the specific actions and resources the role needs.")


# ---------------------------------------------------------------------------
# 2. ENCRYPTION AUDIT
# ---------------------------------------------------------------------------
def audit_encryption(env):
    category = "Encryption"

    for res in env["resources"]:
        name = f'{res["name"]} ({res["type"]})'
        sensitive = res["contains_sensitive_data"]

        # Check 5: encryption at rest
        add_result(category, "Encryption at rest enabled", name, res["encryption_at_rest"],
                   "HIGH" if sensitive else "MEDIUM",
                   "Data is stored without encryption at rest.",
                   "Enable encryption at rest (e.g. AES-256) using the cloud KMS.")

        # Check 6: encryption in transit (TLS)
        add_result(category, "Encryption in transit (TLS) enabled", name,
                   res["encryption_in_transit"],
                   "HIGH" if sensitive else "MEDIUM",
                   "Data moves between services without TLS.",
                   "Enforce TLS 1.2+ on all endpoints and pipeline connections.")

        # Check 7: sensitive data should use customer-managed keys
        if sensitive:
            add_result(category, "Sensitive data uses customer-managed key", name,
                       res["key_type"] == "customer-managed", "MEDIUM",
                       f'Sensitive data uses key type "{res["key_type"]}".',
                       "Use a customer-managed KMS key with restricted access and rotation.")


# ---------------------------------------------------------------------------
# 3. COMPLIANCE AUDIT (simplified educational checklist)
# ---------------------------------------------------------------------------
def audit_compliance(env):
    category = "Compliance"
    users = env["iam_users"]
    roles = env["iam_roles"]
    resources = env["resources"]
    logs = env["logging_monitoring"]
    keys = env["key_management"]
    storage = [r for r in resources if r["type"] == "Object Storage"]

    # Each control: (id, area, description, passed, severity, issue, remediation)
    controls = [
        ("CTL-01", "Access control", "MFA enforced for all privileged users",
         all(u["mfa_enabled"] for u in users if u["is_admin"] and u["enabled"]),
         "HIGH", "At least one active admin has no MFA.",
         "Enforce MFA through an organisation-wide policy."),

        ("CTL-02", "Access control", "Least privilege: no unapproved wildcard roles",
         not any(role_has_wildcard(r) and not r.get("break_glass_admin_role")
                 for r in roles),
         "HIGH", "Some roles use wildcard permissions.",
         "Review and narrow role policies."),

        ("CTL-03", "Encryption", "All sensitive data encrypted at rest",
         all(r["encryption_at_rest"] for r in resources if r["contains_sensitive_data"]),
         "HIGH", "Sensitive data is stored unencrypted.",
         "Enable default encryption on all data stores."),

        ("CTL-04", "Encryption", "TLS enforced for all resources",
         all(r["encryption_in_transit"] for r in resources),
         "HIGH", "Some resources allow unencrypted traffic.",
         "Enforce TLS on every endpoint and connection."),

        ("CTL-05", "Encryption", "Encryption key rotation enabled",
         keys["key_rotation_enabled"],
         "MEDIUM", "Keys are not rotated.",
         "Enable automatic key rotation (e.g. yearly)."),

        ("CTL-06", "Logging & monitoring", "Audit logging enabled and centralised",
         logs["audit_logging_enabled"] and logs["logs_centralised"],
         "HIGH", "Audit logs are missing or not centralised.",
         "Enable cloud audit logs and send them to a central, protected store."),

        ("CTL-07", "Logging & monitoring",
         f'Log retention >= {env["required_log_retention_days"]} days',
         logs["log_retention_days"] >= env["required_log_retention_days"],
         "MEDIUM", f'Logs kept only {logs["log_retention_days"]} days.',
         "Increase retention to meet the organisation's policy."),

        ("CTL-08", "Logging & monitoring", "Security alerts configured",
         logs["security_alerts_enabled"],
         "MEDIUM", "No alerts for suspicious activity.",
         "Configure alerts for root/admin logins, policy changes and public exposure."),

        ("CTL-09", "Secure storage", "Public access blocked on all storage",
         not any(s.get("public_access") for s in storage),
         "HIGH", "At least one storage bucket is publicly accessible.",
         "Turn on 'block public access' at account and bucket level."),

        ("CTL-10", "Secure storage", "Versioning enabled on all storage (recovery)",
         all(s.get("versioning_enabled") for s in storage),
         "LOW", "Some buckets cannot recover overwritten or deleted objects.",
         "Enable object versioning and lifecycle rules."),
    ]

    for ctl_id, area, desc, passed, sev, issue, fix in controls:
        add_result(category, f"{ctl_id} {desc}", area, passed, sev, issue, fix)

    # Detailed per-bucket check so the examiner sees WHICH bucket is public
    for s in storage:
        add_result("Secure Storage", "Bucket is not publicly accessible", s["name"],
                   not s.get("public_access"), "HIGH",
                   "Bucket allows public access; data could be exposed to anyone.",
                   "Block public access and review the bucket policy/ACLs.")


# ---------------------------------------------------------------------------
# 4. REPORTING
# ---------------------------------------------------------------------------
def build_summary():
    failed = [r for r in results if r["status"] == "FAIL"]
    high = sum(1 for r in failed if r["severity"] == "HIGH")
    medium = sum(1 for r in failed if r["severity"] == "MEDIUM")
    low = sum(1 for r in failed if r["severity"] == "LOW")

    if high > 0:
        status = "AT RISK - high-risk findings need immediate action"
    elif medium > 0:
        status = "NEEDS IMPROVEMENT - medium-risk gaps found"
    elif low > 0:
        status = "GOOD - only minor improvements needed"
    else:
        status = "SECURE - all checks passed"

    total = len(results)
    return {
        "total_checks": total,
        "passed": total - len(failed),
        "failed": len(failed),
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "pass_rate_percent": round((total - len(failed)) * 100 / total, 1) if total else 0,
        "overall_status": status,
    }


def print_report(env, summary):
    line = "=" * 78
    print(line)
    print("            CLOUD SECURITY AUDIT REPORT (Educational Assessment)")
    print(line)
    print(f"Environment : {env['environment_name']}")
    print(f"Provider    : {env['cloud_provider']}")
    print(f"Audit date  : {env['audit_date']}")
    print(line)

    # Section-wise results
    for category in ["Access Control", "Encryption", "Compliance", "Secure Storage"]:
        rows = [r for r in results if r["category"] == category]
        if not rows:
            continue
        passed = sum(1 for r in rows if r["status"] == "PASS")
        print(f"\n[{category.upper()}]  {passed}/{len(rows)} checks passed")
        for r in rows:
            tag = "PASS" if r["status"] == "PASS" else f"FAIL-{r['severity']}"
            print(f"  [{tag:<11}] {r['check']}  ->  {r['target']}")

    # Findings sorted by severity
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    failed = sorted([r for r in results if r["status"] == "FAIL"],
                    key=lambda r: order[r["severity"]])
    print("\n" + line)
    print("FINDINGS AND RECOMMENDED CORRECTIVE ACTIONS")
    print(line)
    for i, r in enumerate(failed, start=1):
        print(f"F-{i:02d} [{r['severity']}] {r['check']} -> {r['target']}")
        print(f"      Issue : {r['issue']}")
        print(f"      Fix   : {r['remediation']}")

    print("\n" + line)
    print("SUMMARY")
    print(line)
    print(f"Total checks performed : {summary['total_checks']}")
    print(f"Passed checks          : {summary['passed']}")
    print(f"Failed checks          : {summary['failed']}")
    print(f"High-risk findings     : {summary['high_risk']}")
    print(f"Medium-risk findings   : {summary['medium_risk']}")
    print(f"Low-risk findings      : {summary['low_risk']}")
    print(f"Pass rate              : {summary['pass_rate_percent']}%")
    print(f"Overall security status: {summary['overall_status']}")
    print(line)
    print("DISCLAIMER: Simplified educational checklist inspired by ISO 27001, CIS")
    print("benchmarks and cloud best practices. It does NOT certify compliance, and")
    print("the data audited is fictional sample data, not a real cloud account.")
    print(line)


def save_json_report(env, summary, report_name=None):
    os.makedirs(REPORTS_DIR, exist_ok=True)  # create reports/ automatically
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if report_name:
        # Custom name; never overwrite an existing report
        base = os.path.basename(report_name)
        if not base.endswith(".json"):
            base += ".json"
        path = os.path.join(REPORTS_DIR, base)
        if os.path.exists(path):
            path = os.path.join(REPORTS_DIR, base[:-5] + f"_{timestamp}.json")
    else:
        path = os.path.join(REPORTS_DIR, f"audit_report_{timestamp}.json")

    report = {
        "report_generated_at": datetime.now().isoformat(timespec="seconds"),
        "environment": env["environment_name"],
        "audit_date": env["audit_date"],
        "disclaimer": ("Simplified educational assessment on fictional sample data. "
                       "Not a certification of ISO 27001, CIS or any other standard."),
        "summary": summary,
        "findings": [r for r in results if r["status"] == "FAIL"],
        "all_checks": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    return path


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    report_name = sys.argv[2] if len(sys.argv) > 2 else None
    # Look for the input next to main.py if it is not in the current folder
    if not os.path.exists(input_file) and os.path.exists(os.path.join(BASE_DIR, input_file)):
        input_file = os.path.join(BASE_DIR, input_file)
    env = load_environment(input_file)

    audit_access_control(env)
    audit_encryption(env)
    audit_compliance(env)

    summary = build_summary()
    print_report(env, summary)
    path = save_json_report(env, summary, report_name)
    print(f"\nJSON report saved to: {path}")


if __name__ == "__main__":
    main()
