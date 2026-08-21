"""ClientFactory's default-profile fallback.

The interesting property here isn't "it picks the scanner profile" -- it's
that it never invents a profile that doesn't exist. boto3 raises
ProfileNotFound immediately for an unconfigured name, so forcing
DEFAULT_SCANNER_PROFILE unconditionally would break anyone who didn't create
it (default credentials, an instance role, CI OIDC).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sar_aws_faultline.session import DEFAULT_SCANNER_PROFILE, ClientFactory


def _write_credentials(path: Path, *profiles: str) -> None:
    path.write_text(
        "".join(
            f"[{name}]\naws_access_key_id = testing\naws_secret_access_key = testing\n"
            for name in profiles
        )
    )


@pytest.fixture
def isolated_aws_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point boto3's config resolution at throwaway files.

    Without this, these tests would depend on whatever happens to be in the
    machine's real ~/.aws/ -- exactly the kind of hidden-state flakiness the
    project's fake-credentials fixture exists to avoid.
    """
    creds = tmp_path / "credentials"
    config = tmp_path / "config"
    config.write_text("")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    return creds


def test_falls_back_to_scanner_profile_when_configured(isolated_aws_config: Path):
    _write_credentials(isolated_aws_config, DEFAULT_SCANNER_PROFILE)

    session = ClientFactory()._session()

    assert session.profile_name == DEFAULT_SCANNER_PROFILE


def test_does_not_invent_a_profile_that_does_not_exist(isolated_aws_config: Path):
    _write_credentials(isolated_aws_config, "some-other-profile")

    session = ClientFactory()._session()

    assert session.profile_name == "default"


def test_explicit_profile_wins_over_the_default(isolated_aws_config: Path):
    _write_credentials(isolated_aws_config, DEFAULT_SCANNER_PROFILE, "explicit")

    session = ClientFactory(profile="explicit")._session()

    assert session.profile_name == "explicit"


def test_no_config_files_at_all_falls_back_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """No ~/.aws/ at all (e.g. a fresh CI runner) must not raise."""
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-such-credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-such-config"))

    session = ClientFactory()._session()

    assert session.profile_name == "default"
