"""The request and response bodies of the DLP approval operations, as the contract defines them
(docs/api/openapi.yaml: `ApprovalRequest`, `ApprovalRequestPage`, `ApprovalTransferView`,
`ApprovalTransferFile`, `ApprovalDecision`, `ApprovalApprove`, `ApprovalReject`; #220).
`ApprovalRequestSummary`, `DlpMatchedRule` and `DlpRecipientCheck` are shared with a transfer's
decision (`sft.api.dlp_schemas`).

The generated-spec check compares these with the contract (API README 11.1), with the patterns
of `sft.api.transfer_schemas`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from sft.api.dlp_schemas import (
    ApprovalRequestSummaryOut,
    DlpMatchedRuleOut,
    DlpRecipientCheckOut,
    _optional,
)
from sft.api.transfer_schemas import FileInspectionSummary
from sft.data.models import DlpAction, DlpCondition
from sft.service.approvals import ApprovalPage, ApprovalRequestView
from sft.service.transfer_dlp import threshold_of

ApprovalStateName = Literal["pending", "approved", "rejected", "expired", "withdrawn"]


class ApprovalRequestPageOut(BaseModel):
    model_config = ConfigDict(title="ApprovalRequestPage")

    items: list[ApprovalRequestSummaryOut]
    next_cursor: str | None

    @classmethod
    def of(cls, page: ApprovalPage) -> ApprovalRequestPageOut:
        return cls(
            items=[ApprovalRequestSummaryOut.of(item) for item in page.items],
            next_cursor=page.next_cursor,
        )


class ApprovalDecisionOut(BaseModel):
    model_config = ConfigDict(title="ApprovalDecision")

    approver_id: UUID
    decision: Literal["approve", "reject"]
    comment: str | None = Field(max_length=1000)
    decided_at: datetime


class ApprovalTransferFileOut(BaseModel):
    model_config = ConfigDict(title="ApprovalTransferFile")

    id: UUID
    display_name: str
    size: int = Field(ge=1, le=5_000_000_000)
    inspection: FileInspectionSummary


class ApprovalTransferViewOut(BaseModel):
    """What an approver sees of the transfer. There is never a way to download its files."""

    model_config = ConfigDict(title="ApprovalTransferView")

    created_by: UUID
    message: str | None
    expires_at: datetime | None
    recipients: list[DlpRecipientCheckOut] = Field(max_length=50)
    files: list[ApprovalTransferFileOut] = Field(max_length=50)


class ApprovalRequestOut(BaseModel):
    model_config = ConfigDict(title="ApprovalRequest")

    id: UUID
    transfer_id: UUID
    state: ApprovalStateName
    requested_by: UUID
    requested_at: datetime
    expires_at: datetime
    approvals_required: int = Field(ge=1, le=2)
    approvals: int = Field(ge=0, le=2)
    justification: str = Field(max_length=1000)
    matched_rules: list[DlpMatchedRuleOut] = Field(max_length=50)
    transfer: ApprovalTransferViewOut
    decisions: list[ApprovalDecisionOut] = Field(max_length=2)
    can_decide: bool

    @classmethod
    def of(cls, view: ApprovalRequestView) -> ApprovalRequestOut:
        brief, transfer = view.summary, view.transfer
        return cls(
            id=brief.id,
            transfer_id=brief.transfer_id,
            state=brief.state.value,
            requested_by=brief.requested_by,
            requested_at=brief.requested_at,
            expires_at=brief.expires_at,
            approvals_required=brief.approvals_required,
            approvals=brief.approvals,
            justification=view.justification,
            matched_rules=[
                DlpMatchedRuleOut(
                    rule_id=rule.rule_id,
                    revision=rule.revision,
                    name=rule.name,
                    condition=DlpCondition(rule.condition),
                    action=DlpAction(rule.action),
                    matched_count=rule.matched_count,
                    threshold=threshold_of(rule.condition, rule.threshold),
                )
                for rule in view.matched_rules
            ],
            transfer=ApprovalTransferViewOut(
                created_by=transfer.created_by,
                message=transfer.message,
                expires_at=transfer.expires_at,
                recipients=[
                    DlpRecipientCheckOut(
                        recipient_id=r.recipient_id,
                        email=r.email,
                        trusted=r.trusted,
                        new_domain=r.new_domain,
                    )
                    for r in transfer.recipients
                ],
                files=[
                    ApprovalTransferFileOut(
                        id=f.id,
                        display_name=f.display_name,
                        size=f.size,
                        inspection=FileInspectionSummary(
                            state=f.inspection_state.value,
                            reasons=[r.value for r in f.reasons],
                            dlp_blocked=False,  # received files only (FR-51)
                            detectors=list(f.detectors),
                        ),
                    )
                    for f in transfer.files
                ],
            ),
            decisions=[
                ApprovalDecisionOut(
                    approver_id=d.approver_id,
                    decision=d.decision.value,
                    comment=d.comment,
                    decided_at=d.decided_at,
                )
                for d in view.decisions
            ],
            can_decide=view.can_decide,
        )


Comment = Annotated[str | None, _optional({"type": "string", "minLength": 1, "maxLength": 1000})]


class ApprovalApprove(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: Comment = Field(default=None, min_length=1, max_length=1000)


class ApprovalReject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str = Field(min_length=1, max_length=1000)
