"""
Dummy Backend for Testing - ReliabilityAgent 
Acts as a test client that sends events to Member A (main.py) which then forwards to Member B.
"""
from datetime import datetime
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from loguru import logger
import sys
import uvicorn
import httpx
import asyncio


# Configuration
MEMBER_A_URL = "http://localhost:8000/webhook/event"  # Main.py webhook endpoint

# HTTP client for sending events to Member A
http_client = None

async def get_http_client():
    """Get or create HTTP client."""
    global http_client
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=30.0)
    return http_client

async def cleanup_http_client():
    """Cleanup HTTP client."""
    global http_client
    if http_client:
        await http_client.aclose()
        http_client = None
# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level="INFO"
)

# Event schema matching raw_events table structure
class EventIn(BaseModel):
    """Input schema for incoming events from Member A - matches raw_events schema exactly."""
    source: str = Field(..., description="Source of the event (e.g., 'comments-service')")
    type: str = Field(..., description="Type of event (e.g., 'http_request', 'metric')")
    payload: str = Field(..., description="Raw payload string (log line or HTTP body)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    event_timestamp: datetime = Field(..., description="RFC3339/ISO8601 timestamp when event occurred")
    
    @validator('event_timestamp', pre=True, always=True)
    def parse_timestamp(cls, v):
        """Ensure timestamp is properly formatted."""
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                return datetime.fromisoformat(v)
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
                "payload": "POST /api/comments HTTP/1.1\nContent-Type: application/json\n\n{\"comment\":\"<script>alert('XSS')</script>\"}",
                "metadata": {
                    "env": "staging",
                    "service": "comments",
                    "deploy": "v1.2.3",
                    "severity": "high"
                },
                "event_timestamp": "2025-09-21T12:34:56.789Z"
            }
        }


class EventResponse(BaseModel):
    """Response schema for received events."""
    status: str = "received"
    source: str
    event_timestamp: datetime
    metadata: Dict[str, Any]
    
    class Config:
        schema_extra = {
            "example": {
                "status": "received",
                "source": "comments-service",
                "event_timestamp": "2025-09-21T12:34:56.789Z",
                "metadata": {
                    "env": "staging",
                    "service": "comments",
                    "deploy": "v1.2.3"
                }
            }
        }


class TestEventResponse(BaseModel):
    """Response from sending a test event."""
    status: str
    message: str
    event_sent: Dict[str, Any]
    member_a_response: Dict[str, Any] = None
    timestamp: datetime


# Create FastAPI app
app = FastAPI(
    title="ReliabilityAgent Dummy Backend (Member B)",
    description="Dummy backend service for testing event forwarding from Member A",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Log startup information."""
    logger.info("Starting ReliabilityAgent Test Client (Dummy Backend)")
    logger.info(f"Will send test events to Member A at: {MEMBER_A_URL}")
    logger.info("Use POST /send-test-event to trigger the flow")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down test client")
    await cleanup_http_client()


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "ReliabilityAgent Test Client",
        "role": "Dummy Backend (Test Event Generator)",
        "version": "1.0.0",
        "status": "running",
        "description": "Sends test events to Member A (main.py) which forwards to Member B",
        "member_a_url": MEMBER_A_URL,
        "endpoints": {
            "send_test_event": "POST /send-test-event?event_type=http_request",
            "receive_events": "POST /raw_events (for testing only)",
            "health": "GET /health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "dummy-backend",
        "role": "Member B",
        "timestamp": datetime.utcnow(),
        "ready_to_receive": True
    }


@app.post("/raw_events", response_model=EventResponse)
async def receive_raw_event(event: EventIn):
    """
    Receive raw events from Member A for testing integration.
    
    This endpoint:
    1. Validates the incoming event against the raw_events schema
    2. Logs key information including source, type, timestamp, and metadata
    3. Returns a confirmation response
    
    In the real Member B, this would trigger classification and storage.
    """
    try:
        # Log the received event details
        logger.info(f"📥 Received event from Member A:")
        logger.info(f"   Source: {event.source}")
        logger.info(f"   Type: {event.type}")
        logger.info(f"   Timestamp: {event.event_timestamp}")
        logger.info(f"   Payload length: {len(event.payload)} characters")
        
        # Log metadata details
        if event.metadata:
            logger.info(f"   Metadata:")
            for key, value in event.metadata.items():
                logger.info(f"     {key}: {value}")
        else:
            logger.info(f"   Metadata: (none)")
        
        # Log payload preview (first 200 chars)
        payload_preview = event.payload[:200] + "..." if len(event.payload) > 200 else event.payload
        logger.info(f"   Payload preview: {payload_preview}")
        
        # Create response
        response = EventResponse(
            source=event.source,
            event_timestamp=event.event_timestamp,
            metadata=event.metadata
        )
        
        logger.info(f"✅ Successfully processed event from {event.source}")
        return response
        
    except Exception as e:
        logger.error(f"❌ Error processing event: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process event: {str(e)}")


@app.get("/stats")
async def get_stats():
    """Get basic stats about received events (for testing)."""
    return {
        "message": "This is a dummy backend - no real stats stored",
        "note": "In real Member B, this would show classification results",
        "uptime": "N/A",
        "events_processed": "N/A"
    }


@app.post("/send-test-event", response_model=TestEventResponse)
async def send_test_event(event_type: str = "http_request"):
    """
    Send a test event to Member A (main.py) which will then forward it to Member B.
    
    This simulates the complete flow:
    1. Test Client (this) → Member A (main.py webhook)
    2. Member A → Member B (ngrok URL)
    """
    try:
        # Create a test event
        test_event = {
            "source": "test-client",
            "type": event_type,
            "payload": f"Test {event_type} event from dummy backend at {datetime.utcnow()}",
            "metadata": {
                "test": True,
                "generated_by": "dummy_backend",
                "timestamp": datetime.utcnow().isoformat()
            },
            "event_timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"🚀 Sending test event to Member A at {MEMBER_A_URL}")
        logger.info(f"   Event type: {event_type}")
        
        # Send to Member A (main.py)
        client = await get_http_client()
        response = await client.post(
            MEMBER_A_URL,
            json=test_event,
            headers={"Content-Type": "application/json"}
        )
        
        # Parse response
        try:
            member_a_response = response.json()
        except:
            member_a_response = {"text": response.text, "status_code": response.status_code}
        
        logger.info(f"✅ Member A responded with status: {response.status_code}")
        logger.info(f"   Response: {member_a_response}")
        
        return TestEventResponse(
            status="success" if response.status_code == 200 else "error",
            message=f"Test event sent to Member A, status: {response.status_code}",
            event_sent=test_event,
            member_a_response=member_a_response,
            timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"❌ Failed to send test event: {e}")
        return TestEventResponse(
            status="error",
            message=f"Failed to send test event: {str(e)}",
            event_sent=test_event if 'test_event' in locals() else {},
            timestamp=datetime.utcnow()
        )


if __name__ == "__main__":
    logger.info("🚀 Starting Dummy Backend on http://0.0.0.0:9000")
    uvicorn.run(
        "dummy_backend:app",
        host="0.0.0.0",
        port=9000,
        reload=True,
        log_level="info"
    )