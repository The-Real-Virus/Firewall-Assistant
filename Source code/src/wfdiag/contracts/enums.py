"""Stable evidence labels; these are not probability estimates."""

from enum import StrEnum


class Category(StrEnum):
    EXPLICIT_BLOCK = "EXPLICIT_BLOCK"
    DEFAULT_BLOCK = "DEFAULT_BLOCK"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    LOCAL_RULE_MERGE_RESTRICTED = "LOCAL_RULE_MERGE_RESTRICTED"
    UNRESOLVED_WFP_BLOCK = "UNRESOLVED_WFP_BLOCK"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    NO_RELEVANT_EVENT = "NO_RELEVANT_EVENT"


class EvidenceGrade(StrEnum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    UNKNOWN = "unknown"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class Profile(StrEnum):
    DOMAIN = "Domain"
    PRIVATE = "Private"
    PUBLIC = "Public"


class Completeness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class SourceState(StrEnum):
    COMPLETE = "complete"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"
    ACCESS_DENIED = "access_denied"
    ERROR = "error"
    TRUNCATED = "truncated"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"


class Relevance(StrEnum):
    RELEVANT = "relevant"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class Operation(StrEnum):
    DOCTOR = "doctor"
    COLLECT = "collect"
    ANALYZE = "analyze"
    REPORT = "report"
    PROPOSE = "propose"
    COMPARE = "compare"


class NextStep(StrEnum):
    VERIFY_INTENT = "VERIFY_INTENT"
    REVIEW_POLICY_OWNER = "REVIEW_POLICY_OWNER"
    COLLECT_APPROVED_EVIDENCE = "COLLECT_APPROVED_EVIDENCE"
    REVIEW_WINDOW = "REVIEW_WINDOW"
    REVIEW_LIMITATIONS = "REVIEW_LIMITATIONS"
    GLOSSARY_PROFILE = "GLOSSARY_PROFILE"
    GLOSSARY_AUDITING = "GLOSSARY_AUDITING"
