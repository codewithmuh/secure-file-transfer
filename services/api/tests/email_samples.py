"""One sample of every email, and its variants, with values a test can find in the output."""

from datetime import UTC, datetime
from uuid import UUID

from sft.service.email.catalog import (
    ApiKeyExpiring,
    ApiKeyFirstExport,
    DlpApprovalDecided,
    DlpApprovalExpired,
    DlpApprovalRequested,
    DlpApproverDeactivated,
    DlpConfirmationNeeded,
    DlpNoEligibleApprover,
    DlpPolicyChanged,
    Email,
    EmailType,
    FilesArrived,
    FilesBlockedMember,
    FilesBlockedUploader,
    FirstDownload,
    InvitationAddressInUse,
    MemberInvitation,
    MemberInvitationSso,
    MemberReenrolment,
    PolicyChange,
    RecipientLocked,
    TenantAdminRecovered,
    TransferHeld,
    TransferLink,
    TransferReturnedToDraft,
    UploadRequest,
    VerificationCode,
)

ORIGIN = "https://app.sft.example"
TENANT = "Example Trading K.K."
SENDER = "sender@customer.example"
EXPIRES = datetime(2026, 11, 20, 3, 0, tzinfo=UTC)  # 12:00 in Japan
TRANSFER_ID = UUID("5f0c1f6e-1d7b-4a43-9a43-1c1c7f0a0001")
REQUEST_ID = UUID("5f0c1f6e-1d7b-4a43-9a43-1c1c7f0a0002")
KEY_PREFIX = "sft_dev_" + "Ab3dEf7h"  # a prefix only, never a key
ADMIN = "admin@customer.example"
RECOVERED = datetime(2026, 11, 17, 3, 0, tzinfo=UTC)

# Secrets, each distinct, so a test sees exactly where each one appears.
LINK_TOKEN = "LINKtokenLINKtokenLINKtokenLINKtokenLINKtok"  # noqa: S105 - fake
UPLOAD_TOKEN = "UPLDtokenUPLDtokenUPLDtokenUPLDtokenUPLDtok"  # noqa: S105 - fake
INVITE_TOKEN = "INVTtokenINVTtokenINVTtokenINVTtokenINVTtok"  # noqa: S105 - fake
CODE = "482916"
PASSWORD = "Tmp-Pass-9xQ7!"  # noqa: S105 - a fake temporary password
REENROL_PASSWORD = "Tmp-Reen-4kW2!"  # noqa: S105 - a fake temporary password

SAMPLES: dict[EmailType, Email] = {
    e.TYPE: e
    for e in (
        MemberInvitation(tenant_name=TENANT, temporary_password=PASSWORD, valid_days=7),
        MemberInvitationSso(tenant_name=TENANT, token=INVITE_TOKEN, expires_at=EXPIRES),
        InvitationAddressInUse(tenant_name=TENANT),
        MemberReenrolment(tenant_name=TENANT, temporary_password=REENROL_PASSWORD, valid_days=1),
        TransferLink(tenant_name=TENANT, sender_email=SENDER, token=LINK_TOKEN, expires_at=EXPIRES),
        UploadRequest(
            tenant_name=TENANT, sender_email=SENDER, token=UPLOAD_TOKEN, expires_at=EXPIRES
        ),
        VerificationCode(tenant_name=TENANT, code=CODE),
        FilesBlockedUploader(tenant_name=TENANT, sender_email=SENDER),
        FirstDownload(tenant_name=TENANT, transfer_id=TRANSFER_ID),
        FilesArrived(tenant_name=TENANT, upload_request_id=REQUEST_ID, file_count=1),
        FilesBlockedMember(tenant_name=TENANT, upload_request_id=REQUEST_ID, file_count=1),
        TransferHeld(tenant_name=TENANT, transfer_id=TRANSFER_ID),
        TransferReturnedToDraft(tenant_name=TENANT, transfer_id=TRANSFER_ID),
        RecipientLocked(tenant_name=TENANT, subject_kind="transfer", subject_id=TRANSFER_ID),
        DlpConfirmationNeeded(tenant_name=TENANT, transfer_id=TRANSFER_ID),
        DlpApprovalRequested(tenant_name=TENANT),
        DlpApprovalDecided(tenant_name=TENANT, transfer_id=TRANSFER_ID, decision="approved"),
        DlpApprovalExpired(tenant_name=TENANT, transfer_id=TRANSFER_ID),
        DlpNoEligibleApprover(tenant_name=TENANT),
        DlpPolicyChanged(tenant_name=TENANT, changes=(PolicyChange.RULE_ADDED,)),
        ApiKeyExpiring(tenant_name=TENANT, key_prefix=KEY_PREFIX, expires_at=EXPIRES),
        ApiKeyFirstExport(tenant_name=TENANT, key_prefix=KEY_PREFIX),
        DlpApproverDeactivated(tenant_name=TENANT, none_left=True),
        TenantAdminRecovered(tenant_name=TENANT, admin_email=ADMIN, recovered_at=RECOVERED),
    )
}

# The other side of every branch in a template, so each one renders in both languages.
VARIANTS: list[Email] = [
    *SAMPLES.values(),
    MemberInvitation(tenant_name=TENANT, temporary_password=PASSWORD, valid_days=1),
    MemberReenrolment(tenant_name=TENANT, temporary_password=REENROL_PASSWORD, valid_days=3),
    VerificationCode(tenant_name=TENANT, code="12345678", valid_minutes=5),
    FilesArrived(tenant_name=TENANT, upload_request_id=REQUEST_ID, file_count=12),
    FilesBlockedMember(tenant_name=TENANT, upload_request_id=REQUEST_ID, file_count=3),
    RecipientLocked(tenant_name=TENANT, subject_kind="upload_request", subject_id=REQUEST_ID),
    DlpApprovalRequested(tenant_name=TENANT, request_count=21),
    DlpApprovalDecided(tenant_name=TENANT, transfer_id=TRANSFER_ID, decision="rejected"),
    DlpPolicyChanged(tenant_name=TENANT, changes=tuple(PolicyChange)),
    DlpApproverDeactivated(tenant_name=TENANT, none_left=False),
    TenantAdminRecovered(
        tenant_name=TENANT, admin_email=ADMIN, recovered_at=RECOVERED, temporary_until=EXPIRES
    ),
]

SECRETS: dict[str, EmailType] = {
    LINK_TOKEN: EmailType.TRANSFER_LINK,
    UPLOAD_TOKEN: EmailType.UPLOAD_REQUEST,
    INVITE_TOKEN: EmailType.MEMBER_INVITATION_SSO,
    CODE: EmailType.VERIFICATION_CODE,
    PASSWORD: EmailType.MEMBER_INVITATION,
    REENROL_PASSWORD: EmailType.MEMBER_REENROLMENT,
}
"""Each secret value, and the one email it may appear in."""
