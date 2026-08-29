"""Customer-managed KMS keys without automatic rotation.

Narrowed deliberately to avoid the false-positive modes a naive "is rotation
on" check falls into:

- AWS-managed keys (``aws/s3``, ``aws/ebs``, ...) are excluded. AWS rotates
  these on its own schedule and the account owner cannot toggle it, so
  flagging them would be noise about a setting nobody can act on.
- Asymmetric and HMAC keys are excluded. AWS KMS does not support automatic
  rotation for them at all -- calling GetKeyRotationStatus on one either
  errors or is meaningless, depending on key type, so they are filtered out
  before that call is even made.
- Disabled keys are excluded. A disabled key is not doing cryptographic work,
  so its rotation posture is not a live finding.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass

from botocore.exceptions import ClientError

from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import (
    AuditImpact,
    Effort,
    Finding,
    Remediation,
    Scope,
    Severity,
)
from sar_aws_faultline.registry import register

_ROTATABLE_KEY_SPEC = "SYMMETRIC_DEFAULT"


@dataclass(frozen=True, slots=True)
class KmsKeyState:
    key_id: str
    key_manager: str
    enabled: bool
    key_spec: str
    rotation_enabled: bool


def rotation_missing(state: KmsKeyState) -> bool:
    """Pure. Only a customer-managed, enabled, rotatable-spec key is even
    eligible -- see the module docstring for why each of these is excluded
    rather than just reading the raw rotation flag."""
    if state.key_manager != "CUSTOMER":
        return False
    if not state.enabled:
        return False
    if state.key_spec != _ROTATABLE_KEY_SPEC:
        return False
    return not state.rotation_enabled


@register
class KmsKeyRotationDisabled:
    id = "kms-key-rotation-disabled"
    title = "Customer-managed KMS keys without automatic rotation"
    service = "kms"
    resource_type = "AWS::KMS::Key"
    scope = Scope.REGIONAL
    severity = Severity.LOW
    audit_impact = AuditImpact.HARDENING
    rationale = (
        "Automatic key rotation generates new cryptographic material every "
        "year while keeping old versions available to decrypt data already "
        "encrypted with them, at no cost and with no application changes "
        "required. It limits how much data any single key version protects, "
        "which is standard defense-in-depth practice rather than a response "
        "to any specific threat -- this is good hygiene, not an urgent gap."
    )
    remediation = Remediation(
        summary="Turn on automatic annual rotation for the key.",
        effort=Effort.MINUTES,
        console_steps=(
            "KMS console -> Customer managed keys -> select the key -> Key "
            "rotation tab -> enable 'Automatically rotate this KMS key every "
            "year'.",
        ),
        cli_commands=("aws kms enable-key-rotation --key-id <KEY_ID>",),
        monthly_cost_usd=0.0,
        cost_note=(
            "Rotation itself is free; it does not create a new key resource to bill separately."
        ),
        caveats=(
            "Rotation changes the key's cryptographic material, not its key "
            "ID or ARN -- nothing referencing the key by ID needs to change, "
            "but anything that pinned a specific key *version* outside KMS "
            "(rare) would need review.",
        ),
    )
    required_actions = frozenset({"kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        kms = ctx.client()
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                state = self._state(kms, key["KeyId"])
                if state is None:
                    continue
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(kms, key_id: str) -> KmsKeyState | None:
        try:
            metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            return None

        key_manager = metadata.get("KeyManager", "CUSTOMER")
        enabled = bool(metadata.get("Enabled", False))
        key_spec = metadata.get("KeySpec", _ROTATABLE_KEY_SPEC)

        rotation_enabled = False
        if key_manager == "CUSTOMER" and enabled and key_spec == _ROTATABLE_KEY_SPEC:
            with contextlib.suppress(ClientError):
                rotation_enabled = bool(
                    kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                )

        return KmsKeyState(
            key_id=key_id,
            key_manager=key_manager,
            enabled=enabled,
            key_spec=key_spec,
            rotation_enabled=rotation_enabled,
        )

    def _evaluate(self, ctx: ScanContext, state: KmsKeyState) -> Finding | None:
        if not rotation_missing(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.key_id,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="KMS key without automatic rotation",
            detail="Customer-managed key does not have automatic annual rotation enabled",
            metadata={"key_manager": state.key_manager, "key_spec": state.key_spec},
        )
