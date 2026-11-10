"""AI-only schemas; never carry credentials, raw evidence or an engine write handle."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from wfdiag.contracts.base import Contract, NonExecutable, Sha256
from wfdiag.contracts.enums import Category, Completeness, EvidenceGrade, NextStep, Relevance
from wfdiag.storage.json_input import checked_json

Question = Annotated[str, Field(min_length=1, max_length=1000)]
PublicReference = Annotated[str, Field(pattern=r"^[FE][A-Z0-9]{8,24}$")]
Code = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
ModelId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]


class Provider(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


class AiState(StrEnum):
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    READY = "ready"
    REVIEWING = "reviewing"
    SENDING = "sending"
    ANSWERED = "answered"
    REFUSED = "refused"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    CANCELLED = "cancelled"
    QUOTA_REACHED = "quota_reached"
    FAILED = "failed"


class AiErrorCode(StrEnum):
    DISABLED = "AI_DISABLED"
    CONFIGURATION = "AI_CONFIGURATION"
    CREDENTIAL_STORAGE = "AI_CREDENTIAL_STORAGE"
    AUTHENTICATION = "AI_AUTHENTICATION"
    QUOTA = "AI_QUOTA"
    RATE_LIMIT = "AI_RATE_LIMIT"
    CREDIT = "AI_CREDIT_UNAVAILABLE"
    MODEL_UNAVAILABLE = "AI_MODEL_UNAVAILABLE"
    NETWORK = "AI_NETWORK"
    TIMEOUT = "AI_TIMEOUT"
    CANCELLED = "AI_CANCELLED"
    DISCLOSURE = "AI_DISCLOSURE_BLOCKED"
    STALE_CONSENT = "AI_STALE_CONSENT"
    RESPONSE_INVALID = "AI_RESPONSE_INVALID"
    RESPONSE_UNSAFE = "AI_RESPONSE_UNSAFE"
    POLICY = "AI_PROVIDER_POLICY"
    PROVIDER_FAILURE = "AI_PROVIDER_FAILURE"


class AiConfiguration(Contract):
    enabled: bool = False
    provider: Provider | None = None
    model: ModelId | None = None
    remember_key: bool = False
    persist_conversation: NonExecutable = False
    policy_mode: Literal["free_or_unknown", "permitted_case"] = "free_or_unknown"
    organization_permission_confirmed: bool = False
    provider_policy_confirmed: bool = False


class AiObservation(Contract):
    reference: PublicReference
    code: Code


class AiContext(Contract):
    schema_version: Literal["1.0"] = "1.0"
    finding_ref: PublicReference
    category: Category
    evidence_grade: EvidenceGrade
    completeness: Completeness
    relevance: Relevance
    proposal_eligible: bool
    refusal_codes: Annotated[tuple[Code, ...], Field(max_length=20)]
    protocol: Literal["TCP"] | None
    direction: Literal["inbound", "outbound", "unknown"]
    address_family: Literal["IPv4", "IPv6", "unknown"]
    service_port: Annotated[int, Field(ge=1, le=65535)] | None
    application_alias: Literal["Application A"] = "Application A"
    peer_alias: Literal["Peer B"] = "Peer B"
    observations: Annotated[tuple[AiObservation, ...], Field(max_length=5)]
    limitation_codes: Annotated[tuple[Code, ...], Field(max_length=20)]
    allowed_next_steps: Annotated[tuple[NextStep, ...], Field(max_length=5)]

    @model_validator(mode="after")
    def coherent_context(self) -> Self:
        refs = [o.reference for o in self.observations]
        if len(refs) != len(set(refs)):
            raise ValueError("AI observation aliases must be distinct")
        if self.proposal_eligible and (
            self.category != Category.DEFAULT_BLOCK
            or self.evidence_grade == EvidenceGrade.UNKNOWN
            or self.relevance != Relevance.RELEVANT
            or self.completeness != Completeness.COMPLETE
            or self.refusal_codes
        ):
            raise ValueError("AI context cannot upgrade engine eligibility")
        if len(self.model_dump_json().encode("utf-8")) > 16 * 1024:
            raise ValueError("AI context exceeds its byte budget")
        return self


class AiRequest(Contract):
    schema_version: Literal["1.0"] = "1.0"
    task_mode: Literal["general_help", "selected_finding"]
    question: Question
    approved_context: AiContext | None
    allowed_next_steps: Annotated[tuple[NextStep, ...], Field(max_length=5)]
    response_schema_version: Literal["1.0"] = "1.0"

    @model_validator(mode="after")
    def context_matches_mode(self) -> Self:
        if (self.task_mode == "selected_finding") != (self.approved_context is not None):
            raise ValueError("General help must have no case context; selected finding requires it")
        if (
            self.approved_context
            and self.allowed_next_steps != self.approved_context.allowed_next_steps
        ):
            raise ValueError("Allowed next steps must match reviewed context")
        return self


class Consent(Contract):
    schema_version: Literal["1.0"] = "1.0"
    provider: Provider
    model: ModelId
    payload_sha256: Sha256
    context_revision: Sha256
    prompt_version: Annotated[str, Field(min_length=1, max_length=64)]
    response_schema_version: Literal["1.0"] = "1.0"


class Explanation(Contract):
    schema_version: Literal["1.0"]
    status: Literal["answered", "insufficient_context", "refused"]
    explanation: Annotated[str, Field(min_length=1, max_length=4000)]
    finding_refs: Annotated[tuple[PublicReference, ...], Field(max_length=5)]
    evidence_refs: Annotated[tuple[PublicReference, ...], Field(max_length=5)]
    next_step_ids: Annotated[tuple[NextStep, ...], Field(max_length=5)]
    limitations: Annotated[tuple[Annotated[str, Field(max_length=300)], ...], Field(max_length=5)]


class AiUsage(Contract):
    input_tokens: Annotated[int, Field(ge=0)] | None = None
    output_tokens: Annotated[int, Field(ge=0)] | None = None
    estimated_cost: Annotated[str, Field(max_length=30)] | None = None
    billing_confirmed: NonExecutable = False


def validate_explanation(data: bytes, request: AiRequest) -> Explanation:
    if len(data) > 256 * 1024:
        raise ValueError("AI response exceeds its byte budget")
    checked_json(data, byte_limit=256 * 1024, max_depth=12, max_values=1024)
    response = Explanation.model_validate_json(data)
    context = request.approved_context
    findings = {context.finding_ref} if context else set()
    evidence = {o.reference for o in context.observations} if context else set()
    if not set(response.finding_refs).issubset(findings):
        raise ValueError("Unknown AI finding reference")
    if not set(response.evidence_refs).issubset(evidence):
        raise ValueError("Unknown AI evidence reference")
    if not set(response.next_step_ids).issubset(request.allowed_next_steps):
        raise ValueError("Unapproved AI next step")
    return response
