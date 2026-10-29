# Cloud Security Audit of a Data Engineering Environment

## Objective
Perform a security audit of a cloud-based data engineering environment covering
**access control, encryption and compliance**, identify security risks, classify
them by severity and recommend corrective actions.

> This is a **simplified educational assessment**. It audits **fictional sample
> data** stored in a JSON file. No real cloud account is accessed, and the result
> does **not** certify compliance with ISO 27001, CIS or any other standard.

## Tools Used
- Python 3 (standard library only: `json`, `os`, `sys`, `datetime`)
- JSON for the simulated cloud configuration and the audit report
- No paid services, API keys or cloud accounts

## Project Structure
```
Cloud_Security_Audit/
    main.py                   # audit program
    sample_environment.json   # fictional cloud configuration (secure + insecure)
    requirements.txt          # no external packages needed
    README.md
    reports/                  # timestamped JSON reports (created automatically)
```

## Sample Environment
The fictional "ShopNova Online Retail" e-commerce data platform contains:
- 5 IAM users and 4 IAM roles (including an ETL service account)
- 3 object storage buckets, 1 data warehouse, 1 data pipeline
- Logging/monitoring and key-management settings

It deliberately mixes secure and insecure settings so the audit finds real failures.

## Audit Methodology
| Area | Checks | Severity of failure |
|---|---|---|
| Access control | Unapproved admin users, wildcard (`*`) permissions, MFA missing, enabled accounts inactive > 90 days | HIGH / MEDIUM |
| Encryption | Encryption at rest, encryption in transit (TLS), customer-managed keys for sensitive data | HIGH / MEDIUM |
| Compliance checklist (CTL-01 to CTL-10) | MFA for admins, least privilege, encryption, TLS, key rotation, audit logging, log retention, alerts, public storage, versioning | HIGH / MEDIUM / LOW |
| Secure storage | Each bucket checked for public access | HIGH |

Steps: load configuration → run checks → record PASS/FAIL with severity →
summarise → print terminal report → save JSON report.

**Overall status rule:** any HIGH finding = *AT RISK*; only MEDIUM = *NEEDS
IMPROVEMENT*; only LOW = *GOOD*; none = *SECURE*.

## How to Run
```bash
cd Cloud_Security_Audit
python main.py            # Windows
python3 main.py           # Linux / macOS
```
Optional – audit a different configuration file:
```bash
python main.py my_environment.json
```

## Sample Output (actual run on the included sample data)
```
[ACCESS CONTROL]  13/18 checks passed
  [FAIL-HIGH  ] Admin privileges are approved  ->  bob.dataengineer
  [FAIL-HIGH  ] MFA is enabled  ->  bob.dataengineer
  [FAIL-MEDIUM] No enabled account inactive > 90 days  ->  dave.contractor
  [FAIL-HIGH  ] No wildcard (*) permissions  ->  DataEngineer
...
Total checks performed : 45
Passed checks          : 27
Failed checks          : 18
High-risk findings     : 11
Medium-risk findings   : 6
Low-risk findings      : 1
Pass rate              : 60.0%
Overall security status: AT RISK - high-risk findings need immediate action

JSON report saved to: .../reports/audit_report_YYYYMMDD_HHMMSS.json
```

## Validation with an AWS-style Test Environment
`test_aws_environment.json` is a second, **fictional** AWS-style environment
(S3 buckets, Redshift, Glue-style ETL, 2 IAM users). No AWS account or API is used.

```bash
python main.py test_aws_environment.json aws_environment_test_report.json
python validate_aws_test.py      # checks expected findings automatically
```
Actual result: 31 checks, 16 passed, 15 failed (10 HIGH, 4 MEDIUM, 1 LOW).
All 7 intentionally insecure settings were detected, and all correctly
configured items passed. Details: `reports/aws_validation_summary.md`.

Notes:
- A second argument sets the report name; an existing report is never overwritten
  (a timestamp is added instead).
- Users marked `"is_service_account": true` skip the MFA check, because programs
  cannot use MFA; their safety comes from least-privilege roles.

## Limitations
- Uses fictional JSON data, not live cloud APIs (AWS/Azure/GCP).
- The checklist is simplified; real audits cover many more controls.
- Severity rules are fixed in code, not a full risk-assessment method.
- Passing these checks does not mean the environment is compliant with any standard.

## Conclusion
The tool shows how a cloud security audit works in practice: collect configuration
evidence, compare it with security controls, classify the gaps by risk and
recommend fixes. On the sample data it found unapproved admin access, missing MFA,
wildcard permissions, unencrypted and public storage, and a pipeline without TLS.
Applying least privilege, MFA, encryption, blocked public access and centralised
logging with alerts would remove these risks. Fixed findings should be re-tested.
