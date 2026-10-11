"""Data contract for the Blue-Team AI firewall. Every model forbids extra fields."""
from decimal import Decimal
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Status(str, Enum):
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"


class Threat(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    ROLEPLAY_ATTACK = "ROLEPLAY_ATTACK"
    MEMO_INJECTION = "MEMO_INJECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNAUTHORIZED_TRANSFER = "UNAUTHORIZED_TRANSFER"
    OBFUSCATION = "OBFUSCATION"
    AMBIGUOUS_INPUT = "AMBIGUOUS_INPUT"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class Intent(str, Enum):
    CHECK_BALANCE = "CHECK_BALANCE"
    TRANSFER = "TRANSFER"
    UNKNOWN = "UNKNOWN"


class ParsedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: Intent
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    recipient: Optional[str] = None
    memo: Optional[str] = None


class LLMVerdict(BaseModel):
    """What we accept back from Gemini. It classifies only; it never decides."""
    model_config = ConfigDict(extra="forbid")
    is_malicious: bool
    threat_category: Threat
    confidence: int = Field(ge=0, le=100)
    reason: str = ""  # free text from the LLM; never used in decisions


class FirewallResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    status: Status
    risk_score: int = Field(ge=0, le=100)
    threat_category: Threat
    explanation: str
    parsed_request: Optional[ParsedRequest] = None  # always None when BLOCKED
    triggered_layers: list[str] = []
