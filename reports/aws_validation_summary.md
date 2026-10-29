# Validation Summary: AWS-style Test Environment

Fictional AWS-style data audited by main.py. This is NOT a real AWS security scan.

Command: `python main.py test_aws_environment.json aws_environment_test_report.json`
Report: `/Users/adeshpatankar/Downloads/Cloud_Security_Audit/reports/aws_environment_test_report_20261027_152033.json`

| Expected item | Expected | Actual | Matched |
|---|---|---|---|
| data_analyst has MFA disabled | FAIL | FAIL (MEDIUM) | YES |
| data_analyst role has wildcard permissions | FAIL | FAIL (HIGH) | YES |
| customer-raw-data is public | FAIL | FAIL (HIGH) | YES |
| customer-raw-data not encrypted at rest | FAIL | FAIL (HIGH) | YES |
| customer-raw-data not encrypted in transit | FAIL | FAIL (HIGH) | YES |
| ETL pipeline not encrypted in transit | FAIL | FAIL (HIGH) | YES |
| Cloud audit logging disabled | FAIL | FAIL (HIGH) | YES |
| etl_service role is least-privilege | PASS | PASS | YES |
| processed-data public access blocked | PASS | PASS | YES |
| processed-data encrypted at rest | PASS | PASS | YES |
| processed-data encrypted in transit | PASS | PASS | YES |
| Redshift encrypted at rest | PASS | PASS | YES |
| Redshift encrypted in transit | PASS | PASS | YES |
| etl_service: MFA check skipped (service account) | SKIPPED | SKIPPED | YES |

Total checks: 31 | Passed: 16 | Failed: 15 (HIGH 10, MEDIUM 4, LOW 1)
Overall status reported: AT RISK - high-risk findings need immediate action

**Validation result: PASSED - all expected results matched**
