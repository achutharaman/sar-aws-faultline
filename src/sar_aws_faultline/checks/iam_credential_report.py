"""Shared IAM credential-report fetch, used by every check that needs it.

Pulled out of iam_root_mfa.py once a second and third check needed the same
report -- root MFA needs one row, iam-user-no-mfa and iam-access-key-stale
need every non-root row. One fetch, three checks, rather than three separate
GenerateCredentialReport polling loops in one scan.
"""

from __future__ import annotations

import csv
import io
import time

ROOT_ROW_USER = "<root_account>"

# The report is generated asynchronously; GetCredentialReport raises
# CredentialReportNotPresent/NotReady until it's done. A handful of short
# retries covers the common case (seconds) without stalling a scan.
_REPORT_POLL_ATTEMPTS = 5
_REPORT_POLL_SECONDS = 1.0


def fetch_report_rows(iam) -> list[dict[str, str]] | None:
    """Every row of the credential report, root included, or None if the
    report never became available within the retry budget."""
    for _ in range(_REPORT_POLL_ATTEMPTS):
        iam.generate_credential_report()
        try:
            report = iam.get_credential_report()
        except (
            iam.exceptions.CredentialReportNotPresentException,
            iam.exceptions.CredentialReportNotReadyException,
        ):
            time.sleep(_REPORT_POLL_SECONDS)
            continue
        except iam.exceptions.CredentialReportExpiredException:
            continue
        return list(csv.DictReader(io.StringIO(report["Content"].decode("utf-8"))))
    return None
