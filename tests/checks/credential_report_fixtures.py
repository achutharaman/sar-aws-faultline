"""Shared credential-report CSV builder for the IAM checks' tests.

Not a test module itself -- pytest only collects test_*.py, so this is safe
to import from the three IAM check test files without becoming a fourth
(empty) test run.
"""

from __future__ import annotations

import csv
import io

HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,"
    "password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
)


def csv_row(
    user: str,
    *,
    password_enabled: str = "false",
    mfa_active: str = "false",
    access_key_1_active: str = "false",
    access_key_1_last_rotated: str = "N/A",
) -> str:
    arn = f"arn:aws:iam::123456789012:{'root' if user == '<root_account>' else 'user/' + user}"
    return (
        f"{user},{arn},2020-01-01T00:00:00Z,{password_enabled},N/A,N/A,N/A,"
        f"{mfa_active},{access_key_1_active},{access_key_1_last_rotated},N/A,N/A,N/A,"
        "false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
    )


def report_bytes(*rows: str) -> bytes:
    return (HEADER + "".join(rows)).encode("utf-8")


def report_rows(*rows: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(HEADER + "".join(rows))))
