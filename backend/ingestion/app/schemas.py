"""
Pydantic schemas for request/response validation.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, validator


class EventIn(BaseModel):
    """Input schema for incoming events - matches raw_events schema exactly."""
    source: str = Field(..., description="Source of the event (e.g., 'comments-service', 'monitoring-system')")
    type: str = Field(..., description="Type of event (e.g., 'http_request', 'metric', 'waf')")
    payload: str = Field(..., description="Raw payload string (log line or HTTP body)")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    event_timestamp: datetime = Field(..., description="RFC3339/ISO8601 timestamp when event occurred")
    
    @validator('event_timestamp', pre=True, always=True)
    def parse_timestamp(cls, v):
        """Ensure timestamp is properly formatted."""
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                return datetime.fromisoformat(v)
        elif v is None:
            return datetime.utcnow()
        return v
    
    @validator('source', 'type', 'payload')
    def validate_required_strings(cls, v):
        """Ensure required string fields are not empty."""
        if not v or not v.strip():
            raise ValueError('Field cannot be empty')
        return v.strip()
    
    class Config:
        schema_extra = {
            "example": {
                "source": "comments-service",
                "type": "http_request",
                "payload": "POST /api/comments HTTP/1.1\nUser-Agent: Mozilla/5.0\n\n{\"comment\":\"<script>alert('XSS')</script>\"}",
                "metadata": {
                    "env": "staging",
                    "service": "comments",
                    "deploy": "v1.2.3",
                    "severity": "high"
                },
                "event_timestamp": "2025-09-21T12:34:56.789Z"
            }
        }


class ForwardResponse(BaseModel):
    """Response schema for forwarded events."""
    status: str = Field(..., description="Status of the forwarding operation")
    forward_response_status: int = Field(..., description="HTTP status code from Member B")
    forward_response_body: Union[Dict[str, Any], str] = Field(..., description="Response body from Member B")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "forwarded",
                "forward_response_status": 200,
                "forward_response_body": {"event_id": 123, "status": "stored"}
            }
        }


class SimulationRequest(BaseModel):
    """Schema for simulation configuration."""
    count: Optional[int] = Field(default=1, ge=1, le=100, description="Number of events to generate")
    delay_seconds: Optional[float] = Field(default=0, ge=0, le=60, description="Delay between events in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "count": 5,
                "delay_seconds": 1.0
            }
        }


class SimulationResponse(BaseModel):
    """Response schema for simulation."""
    message: str
    scenario: str
    events_forwarded: int
    forward_responses: List[ForwardResponse]
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Simulation completed successfully",
                "scenario": "xss",
                "events_forwarded": 3,
                "forward_responses": [
                    {"status": "forwarded", "forward_response_status": 200, "forward_response_body": {"event_id": 124}},
                    {"status": "forwarded", "forward_response_status": 200, "forward_response_body": {"event_id": 125}}
                ]
            }
        }


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    service: str
    version: str
    timestamp: datetime
    member_b_url: str
    member_b_reachable: bool
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "service": "ingestion",
                "version": "1.0.0",
                "timestamp": "2025-09-21T12:34:56.789Z",
                "member_b_url": "http://localhost:9000/raw_events",
                "member_b_reachable": True
            }
        }


class ErrorResponse(BaseModel):
    """Error response schema."""
    status: str = "error"
    detail: str
    
    class Config:
        schema_extra = {
            "example": {
                "status": "error",
                "detail": "Failed to forward event to Member B after 3 retries"
            }
        }