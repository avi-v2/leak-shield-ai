"""
Pydantic schemas for Sentinel AI API requests and responses.
Enforces strict input validation and type safety.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator

class Finding(BaseModel):
    """Details of a single sensitive data or adversarial threat finding."""
    type: str = Field(..., description="Unique code identifier for the rule triggered")
    category: str = Field(..., description="High-level threat category")
    description: str = Field(..., description="Human-readable description of the violation")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., description="Risk severity level")
    match_preview: Optional[str] = Field(None, description="Redacted preview of the pattern match, never raw secret")
    start: Optional[int] = Field(None, description="Start character index in original text")
    end: Optional[int] = Field(None, description="End character index in original text")

class ScanRequest(BaseModel):
    """Payload for POST /scan"""
    prompt: str = Field(..., min_length=1, max_length=20000, description="Raw text prompt to evaluate")

class ScanResponse(BaseModel):
    """Response returned by POST /scan"""
    action: Literal["ALLOW", "REDACT", "BLOCK"]
    risk_level: Literal["low", "medium", "high", "critical"]
    prompt_injection_risk: Literal["none", "low", "medium", "high"]
    findings: List[Finding]
    redacted_prompt: str
    recommendation: str
    scanned_at: str
    request_id: str
    classifier_available: bool = False
    classifier_score: Optional[float] = None
    explanation: Optional[str] = None

class ChatRequest(BaseModel):
    """Payload for POST /chat"""
    prompt: str = Field(..., min_length=1, max_length=20000, description="Prompt to submit through security proxy")
    model: Optional[str] = Field("llama3.2:3b", description="Model proxy target identifier")

class ChatResponse(BaseModel):
    """Response returned by POST /chat"""
    decision: Literal["ALLOW", "REDACT", "BLOCK"]
    request_id: str
    latency_ms: int
    response: Optional[str] = None
    blocked_reason: Optional[str] = None
    findings: Optional[List[Finding]] = None
    timestamp: str

class PolicySettings(BaseModel):
    """Server-side security policy configuration schema."""
    detectApiKeys: bool = Field(True, description="Detect and block API keys and cloud tokens (Mandatory protection)")
    detectCreditCards: bool = Field(True, description="Detect and redact PCI payment cards")
    detectSsn: bool = Field(True, description="Detect and redact US Social Security Numbers")
    detectEmails: bool = Field(True, description="Detect and redact personal email addresses")
    detectPasswords: bool = Field(True, description="Detect and block exposed passwords (Mandatory protection)")
    detectAadhaar: bool = Field(True, description="Detect and redact Indian Aadhaar numbers")
    detectPan: bool = Field(True, description="Detect and redact Indian PAN identifiers")
    detectPhone: bool = Field(True, description="Detect and redact telephone numbers")
    blockPromptInjection: bool = Field(True, description="Analyze and block adversarial prompt injections")
    blockJailbreaks: bool = Field(True, description="Analyze and block persona jailbreaks (e.g. DAN)")
    blockSystemPromptExtraction: bool = Field(True, description="Analyze and block system prompt exfiltration attempts")
    inspectModelOutputs: bool = Field(True, description="Inspect upstream LLM completions before delivering to client")
    defaultAction: Literal["ALLOW", "REDACT", "BLOCK"] = Field("REDACT", description="Default remediation action")
    highRiskThreshold: Literal["medium", "high", "critical"] = Field("high", description="Minimum severity to trigger BLOCK")

    @field_validator("detectApiKeys", "detectPasswords")
    @classmethod
    def enforce_mandatory_credential_protection(cls, v: bool, info) -> bool:
        if not v:
            raise ValueError(f"Mandatory security control '{info.field_name}' cannot be disabled.")
        return True

class EventDetails(BaseModel):
    """Inner details object for an audit event, matching frontend expectations."""
    matched_rules: List[str] = []
    latency_ms: int = 0
    client_ip: str = "127.0.0.1"
    user_agent: str = "Unknown"
    sanitized_preview: str = ""
    is_output_scan: bool = False

class EventResponse(BaseModel):
    """Response schema for a single audit event."""
    id: str
    request_id: Optional[str] = None
    timestamp: str
    threat_category: str
    severity: str
    source: str
    action_taken: str
    status: str
    summary: str
    details: EventDetails
    similarity_score: Optional[float] = None
    semantic_match_percentage: Optional[int] = None

class ImageMetadata(BaseModel):
    """Extracted technical and privacy-related image metadata."""
    format: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    mode: Optional[str] = None
    file_size_bytes: int = 0
    has_exif: bool = False
    gps_coordinates: Optional[Dict[str, Any]] = None
    device_info: Optional[Dict[str, str]] = None

class ImageScanRequest(BaseModel):
    """Payload for POST /scan/image (JSON format with base64 data)."""
    image_base64: str = Field(..., description="Base64 encoded image data or data URI")
    filename: Optional[str] = Field("uploaded_image.png", description="Original image filename")

class ImageScanResponse(BaseModel):
    """Response schema for image privacy and sensitive data scan."""
    request_id: str
    action: Literal["ALLOW", "REDACT", "BLOCK"]
    risk_level: Literal["low", "medium", "high", "critical"]
    findings: List[Finding]
    metadata: ImageMetadata
    recommendation: str
    sanitized_image_base64: Optional[str] = None
    scanned_at: str
    explanation: Optional[str] = None

class MetricsResponse(BaseModel):
    """Response schema for GET /metrics."""
    total_requests: int
    allowed_requests: int
    blocked_requests: int
    redacted_requests: int
    sensitive_data_detections: int
    injection_detections: int
    traffic_over_time: List[Dict[str, Any]]
    threat_distribution: List[Dict[str, Any]]

class HealthResponse(BaseModel):
    """Response schema for GET /health."""
    status: str
    gateway: str
    version: str
    engine: str
    timestamp: str
    database: bool
    classifier: bool
    llm: bool
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
