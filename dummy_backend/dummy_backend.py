"""
Dummy Backend for Continuous Log Generation - ReliabilityAgent 
Generates realistic logs with malicious payloads for testing Member A detection.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from loguru import logger
import sys
import uvicorn
import asyncio
import random
import json
import httpx
from collections import deque


# Configuration for log generation
class LogGeneratorConfig:
    NORMAL_LOG_INTERVAL = 2.0  # seconds between normal logs
    ERROR_LOG_EVERY_N = 5      # every N logs will be an error (5 × 2s = 10s interval)
    MALICIOUS_LOG_EVERY_N = 15 # every N logs will contain malicious payload
    MAX_LOG_HISTORY = 1000     # maximum logs to keep in memory
    
    # Webhook settings
    INGESTION_WEBHOOK_URL = "http://localhost:8000/webhook/error-log"  # Member A webhook endpoint
    ENABLE_WEBHOOKS = True     # Enable webhook notifications for error logs
    
    # Malicious payload templates
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "javascript:document.cookie",
        "<svg onload=alert(1)>",
        "<s c r i p t>alert('obfuscated')</s c r i p t>",
        "data:text/html,<script>alert(1)</script>",
        "<input onfocus=alert(1) autofocus>",
        "expression(alert('XSS'))",
        "vbscript:alert('XSS')"
    ]
    
    SQLI_PAYLOADS = [
        "admin' OR 1=1 --",
        "' UNION SELECT password FROM users --",
        "'; DROP TABLE users; --",
        "admin'/**/OR/**/1=1",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
        "' OR SLEEP(5) --",
        "' UNION SELECT @@VERSION --",
        "admin' OR '1'='1",
        "' OR 1=1 LIMIT 1 --",
        "1'; WAITFOR DELAY '00:00:05' --"
    ]
    
    SSRF_PAYLOADS = [
        "GET http://169.254.169.254/latest/meta-data/",
        "curl http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/user-data",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/xHELO",
        "http://localhost:6379/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://192.168.1.1/admin",
        "ftp://127.0.0.1/",
        "dict://127.0.0.1:11211/"
    ]
    
    DB_ERROR_MESSAGES = [
        "ERROR: connection timed out after 1500ms",
        "Database connection pool exhausted",
        "Query timeout: SELECT * FROM large_table took 5000ms",
        "Deadlock detected in transaction",
        "Could not connect to database server",
        "Connection refused: postgresql://db:5432",
        "DB_TIMEOUT: Query exceeded 2000ms limit",
        "Too many connections to database",
        "Lost connection to MySQL server during query",
        "Database server connection timeout after 30s"
    ]


# Log storage
log_storage = deque(maxlen=LogGeneratorConfig.MAX_LOG_HISTORY)
log_counter = 0
generation_active = True
# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level="INFO"
)


# Log entry model
class LogEntry(BaseModel):
    """Structure for generated log entries."""
    timestamp: str
    service: str = "dummy-service"
    level: str = Field(..., regex="^(DEBUG|INFO|WARN|ERROR)$")
    message: str
    host: str = "dummy-host"
    stack_trace: Optional[str] = None
    payload: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "timestamp": "2025-09-21T12:34:56.789Z",
                "service": "dummy-service",
                "level": "INFO",
                "message": "User login successful",
                "host": "dummy-host",
                "stack_trace": None,
                "payload": None
            }
        }


class LogStreamResponse(BaseModel):
    """Response for log streaming endpoints."""
    logs: List[LogEntry]
    total_count: int
    since: Optional[str] = None
    next_since: Optional[str] = None


def generate_normal_log() -> LogEntry:
    """Generate a normal, benign log entry."""
    normal_messages = [
        "User authentication successful",
        "API request processed in 150ms",
        "Cache hit for user profile data",
        "Database query completed successfully",
        "File upload completed",
        "Session created for user",
        "Email notification sent",
        "Background job started",
        "Configuration reloaded",
        "Health check passed",
        "Memory usage: 45% of allocated heap",
        "Request routed to service instance",
        "Transaction committed successfully",
        "Webhook payload validated",
        "Rate limit check passed"
    ]
    
    return LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        level="INFO",
        message=random.choice(normal_messages),
        payload=json.dumps({"user_id": random.randint(1000, 9999), "action": "normal_operation"})
    )


def generate_error_log_with_stack() -> LogEntry:
    """Generate an error log with realistic Python stack trace."""
    error_messages = [
        "Unhandled exception in request processing",
        "Failed to parse JSON payload",
        "Service unavailable: downstream timeout",
        "Memory allocation failed",
        "File not found in storage bucket",
        "Invalid API key provided",
        "Rate limit exceeded for client",
        "Network connection lost",
        "Permission denied accessing resource",
        "Invalid input validation failed"
    ]
    
    stack_traces = [
        """Traceback (most recent call last):
  File "/app/main.py", line 42, in process_request
    result = await service.handle_request(data)
  File "/app/service.py", line 128, in handle_request
    response = await self.database.query(sql)
  File "/app/database.py", line 67, in query
    return await self.connection.fetch(query)
ConnectionTimeoutError: Query timeout after 5000ms""",
        
        """Traceback (most recent call last):
  File "/app/handlers/auth.py", line 23, in authenticate
    user = await User.get_by_token(token)
  File "/app/models/user.py", line 156, in get_by_token
    decoded = jwt.decode(token, key)
  File "/usr/lib/python3.10/jwt/api_jwt.py", line 125, in decode
    raise InvalidTokenError("Token signature invalid")
InvalidTokenError: Token signature invalid""",
        
        """Traceback (most recent call last):
  File "/app/background/tasks.py", line 89, in process_queue
    item = queue.get_nowait()
  File "/usr/lib/python3.10/queue.py", line 168, in get_nowait
    return self.get(block=False)
  File "/usr/lib/python3.10/queue.py", line 147, in get
    raise Empty
queue.Empty: No items in queue"""
    ]
    
    return LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        level="ERROR",
        message=random.choice(error_messages),
        stack_trace=random.choice(stack_traces),
        payload=json.dumps({"error_code": random.randint(4000, 5999), "correlation_id": f"err-{random.randint(100000, 999999)}"})
    )


def generate_malicious_log() -> LogEntry:
    """Generate a log entry containing malicious payloads for testing."""
    payload_type = random.choice(["xss", "sqli", "ssrf", "db_error"])
    
    if payload_type == "xss":
        payload = random.choice(LogGeneratorConfig.XSS_PAYLOADS)
        message = f"Suspicious user input detected: {payload}"
        level = "WARN"
    elif payload_type == "sqli":
        payload = random.choice(LogGeneratorConfig.SQLI_PAYLOADS)
        message = f"Database query with suspicious parameters: {payload}"
        level = "WARN"
    elif payload_type == "ssrf":
        payload = random.choice(LogGeneratorConfig.SSRF_PAYLOADS)
        message = f"Outbound request to suspicious URL: {payload}"
        level = "WARN"
    else:  # db_error
        message = random.choice(LogGeneratorConfig.DB_ERROR_MESSAGES)
        level = "ERROR"
        payload = json.dumps({"latency": f"{random.randint(1500, 8000)}ms", "query": "SELECT * FROM large_table"})
    
    return LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        level=level,
        message=message,
        payload=payload,
        stack_trace="Stack trace omitted for brevity" if payload_type == "db_error" else None
    )


async def send_webhook_notification(log_entry: LogEntry):
    """Send webhook notification to ingestion service for error/warn logs."""
    if not LogGeneratorConfig.ENABLE_WEBHOOKS:
        return
    
    if log_entry.level not in ["ERROR", "WARN"]:
        return
        
    try:
        webhook_payload = {
            "source": log_entry.service,
            "type": "log",
            "payload": log_entry.message,
            "metadata": {
                "service": log_entry.service,
                "host": log_entry.host,
                "level": log_entry.level,
                "stack_trace": log_entry.stack_trace,
                "original_payload": log_entry.payload,
                "webhook_source": "dummy-backend"
            },
            "event_timestamp": log_entry.timestamp
        }
        
        logger.info(f"📤 WEBHOOK: Sending {log_entry.level} log to ingestion service")
        logger.debug(f"🔗 WEBHOOK URL: {LogGeneratorConfig.INGESTION_WEBHOOK_URL}")
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                LogGeneratorConfig.INGESTION_WEBHOOK_URL,
                json=webhook_payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Source": "dummy-backend",
                    "X-Log-Level": log_entry.level
                }
            )
            
            if response.status_code == 200:
                logger.success(f"✅ WEBHOOK SUCCESS: {log_entry.level} log delivered to ingestion service")
            else:
                logger.warning(f"⚠️  WEBHOOK WARNING: Ingestion service responded with {response.status_code}")
                
    except Exception as e:
        logger.error(f"❌ WEBHOOK FAILED: Could not send {log_entry.level} log to ingestion service: {e}")


async def log_generator_task():
    """Background task that continuously generates logs."""
    global log_counter, generation_active
    
    logger.info("🔄 Starting continuous log generation")
    
    while generation_active:
        try:
            log_counter += 1
            
            # Determine log type based on counters
            if log_counter % LogGeneratorConfig.MALICIOUS_LOG_EVERY_N == 0:
                log_entry = generate_malicious_log()
                logger.debug(f"Generated malicious log #{log_counter}: {log_entry.message[:50]}...")
                # Send webhook for malicious logs (WARN level)
                await send_webhook_notification(log_entry)
            elif log_counter % LogGeneratorConfig.ERROR_LOG_EVERY_N == 0:
                log_entry = generate_error_log_with_stack()
                logger.debug(f"Generated error log #{log_counter}: {log_entry.message}")
                # Send webhook for error logs
                await send_webhook_notification(log_entry)
            else:
                log_entry = generate_normal_log()
                logger.debug(f"Generated normal log #{log_counter}: {log_entry.message}")
                # No webhook for normal logs
            
            # Store the log
            log_storage.append(log_entry)
            
            # Wait before generating next log
            await asyncio.sleep(LogGeneratorConfig.NORMAL_LOG_INTERVAL)
            
        except Exception as e:
            logger.error(f"Error in log generation: {e}")
            await asyncio.sleep(1.0)

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
    title="ReliabilityAgent Log Generator",
    description="Continuous log generation with malicious payloads for testing Member A detection",
    version="2.0.0",
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

# Background task reference
log_generation_task = None


@app.on_event("startup")
async def startup_event():
    """Start log generation and initialize service."""
    global log_generation_task
    
    logger.info("🚀 Starting ReliabilityAgent Log Generator")
    logger.info(f"Normal log interval: {LogGeneratorConfig.NORMAL_LOG_INTERVAL}s")
    logger.info(f"Error log every: {LogGeneratorConfig.ERROR_LOG_EVERY_N} logs")
    logger.info(f"Malicious log every: {LogGeneratorConfig.MALICIOUS_LOG_EVERY_N} logs")
    
    # Start background log generation
    log_generation_task = asyncio.create_task(log_generator_task())
    logger.info("📊 Continuous log generation started")


@app.on_event("shutdown")
async def shutdown_event():
    """Stop log generation and cleanup."""
    global log_generation_task, generation_active
    
    logger.info("🛑 Shutting down log generator")
    generation_active = False
    
    if log_generation_task:
        log_generation_task.cancel()
        try:
            await log_generation_task
        except asyncio.CancelledError:
            pass


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "ReliabilityAgent Log Generator",
        "role": "Continuous Log Generator",
        "version": "2.0.0",
        "status": "running",
        "description": "Generates realistic logs with malicious payloads for testing detection",
        "log_stats": {
            "total_generated": log_counter,
            "logs_in_memory": len(log_storage),
            "generation_active": generation_active
        },
        "endpoints": {
            "logs_recent": "GET /logs/recent?limit=50",
            "logs_stream": "GET /logs/stream?since=timestamp",
            "logs_control": "POST /logs/start, POST /logs/stop",
            "health": "GET /health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "log-generator",
        "generation_active": generation_active,
        "logs_generated": log_counter,
        "logs_in_memory": len(log_storage),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/logs/recent", response_model=LogStreamResponse)
async def get_recent_logs(limit: int = Query(50, ge=1, le=1000)):
    """Get recent ERROR and WARN logs from memory (filters out normal INFO logs)."""
    # Filter to only ERROR and WARN level logs (exclude normal INFO logs)
    error_and_warn_logs = [log for log in log_storage if log.level in ["ERROR", "WARN"]]
    
    # Get the most recent error/warn logs
    recent_logs = error_and_warn_logs[-limit:] if len(error_and_warn_logs) > limit else error_and_warn_logs
    
    next_since = None
    if recent_logs:
        next_since = recent_logs[-1].timestamp
    
    logger.info(f"📤 Returning {len(recent_logs)} ERROR/WARN logs (filtered from {len(log_storage)} total logs)")
    
    return LogStreamResponse(
        logs=recent_logs,
        total_count=len(recent_logs),
        next_since=next_since
    )


@app.get("/logs/stream", response_model=LogStreamResponse)
async def get_logs_since(since: Optional[str] = Query(None)):
    """Get ERROR and WARN logs since a specific timestamp (filters out normal INFO logs)."""
    if not since:
        # If no timestamp provided, return recent ERROR/WARN logs
        return await get_recent_logs(50)
    
    try:
        # Simple and robust timestamp parsing
        since_clean = since.strip()
        
        # Try different parsing approaches
        since_dt = None
        parsing_attempts = [
            # Direct parsing
            lambda x: datetime.fromisoformat(x),
            # With timezone replacement
            lambda x: datetime.fromisoformat(x.replace('Z', '+00:00')),
            # Strip and parse
            lambda x: datetime.fromisoformat(x.replace(' ', '').replace('Z', '+00:00')),
            # Add timezone if missing
            lambda x: datetime.fromisoformat(x + '+00:00') if '+' not in x and 'Z' not in x else datetime.fromisoformat(x)
        ]
        
        for attempt in parsing_attempts:
            try:
                since_dt = attempt(since_clean)
                break
            except:
                continue
        
        if since_dt is None:
            raise ValueError(f"Could not parse timestamp: {since}")
        
        logger.info(f"📅 Filtering ERROR/WARN logs since: {since_dt} (from: {since})")
        
        # Filter logs after the since timestamp AND only ERROR/WARN levels
        filtered_logs = []
        for log in log_storage:
            try:
                # Skip normal INFO logs
                if log.level not in ["ERROR", "WARN"]:
                    continue
                
                # Parse log timestamp consistently
                log_timestamp = log.timestamp
                if log_timestamp.endswith('+00:00'):
                    log_dt = datetime.fromisoformat(log_timestamp)
                elif log_timestamp.endswith('Z'):
                    log_dt = datetime.fromisoformat(log_timestamp.replace('Z', '+00:00'))
                else:
                    log_dt = datetime.fromisoformat(log_timestamp + '+00:00')
                
                # Compare timestamps
                if log_dt > since_dt:
                    filtered_logs.append(log)
            except (ValueError, TypeError) as e:
                logger.warning(f"⚠️  Skipping log with invalid timestamp: {log.timestamp} - {e}")
                continue
        
        next_since = None
        if filtered_logs:
            next_since = filtered_logs[-1].timestamp
        
        logger.info(f"📦 Returning {len(filtered_logs)} ERROR/WARN logs since {since} (total logs in storage: {len(log_storage)})")
        
        return LogStreamResponse(
            logs=filtered_logs,
            total_count=len(filtered_logs),
            since=since,
            next_since=next_since
        )
        
    except (ValueError, TypeError) as e:
        logger.error(f"❌ Timestamp parsing error: {e} for timestamp: {since}")
        raise HTTPException(status_code=400, detail=f"Invalid timestamp format: {e}")


@app.post("/logs/start")
async def start_log_generation():
    """Start log generation."""
    global generation_active, log_generation_task
    
    if generation_active:
        return {"status": "already_running", "message": "Log generation is already active"}
    
    generation_active = True
    log_generation_task = asyncio.create_task(log_generator_task())
    
    logger.info("📊 Log generation restarted via API")
    return {"status": "started", "message": "Log generation started"}


@app.post("/logs/stop")
async def stop_log_generation():
    """Stop log generation."""
    global generation_active, log_generation_task
    
    if not generation_active:
        return {"status": "already_stopped", "message": "Log generation is already stopped"}
    
    generation_active = False
    
    if log_generation_task:
        log_generation_task.cancel()
        try:
            await log_generation_task
        except asyncio.CancelledError:
            pass
    
    logger.info("🛑 Log generation stopped via API")
    return {"status": "stopped", "message": "Log generation stopped"}


@app.get("/logs/stats")
async def get_log_stats():
    """Get log generation statistics."""
    malicious_count = 0
    error_count = 0
    normal_count = 0
    
    for log in log_storage:
        if log.level == "ERROR":
            error_count += 1
        elif any(payload in (log.message + (log.payload or "")) for payload in 
                LogGeneratorConfig.XSS_PAYLOADS + LogGeneratorConfig.SQLI_PAYLOADS + 
                LogGeneratorConfig.SSRF_PAYLOADS):
            malicious_count += 1
        else:
            normal_count += 1
    
    return {
        "total_generated": log_counter,
        "logs_in_memory": len(log_storage),
        "generation_active": generation_active,
        "log_breakdown": {
            "normal": normal_count,
            "error": error_count,
            "malicious": malicious_count
        },
        "configuration": {
            "normal_log_interval": LogGeneratorConfig.NORMAL_LOG_INTERVAL,
            "error_log_every_n": LogGeneratorConfig.ERROR_LOG_EVERY_N,
            "malicious_log_every_n": LogGeneratorConfig.MALICIOUS_LOG_EVERY_N,
            "max_log_history": LogGeneratorConfig.MAX_LOG_HISTORY
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


if __name__ == "__main__":
    logger.info("🚀 Starting Log Generator on http://0.0.0.0:9000")
    uvicorn.run(
        "dummy_backend:app",
        host="0.0.0.0",
        port=9000,
        reload=True,
        log_level="info"
    )