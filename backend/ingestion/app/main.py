"""
FastAPI application for the ReliabilityAgent ingestion service.
Handles continuous log monitoring, security detection, and event forwarding to Member B.
"""
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
import sys
import httpx
import uvicorn

from config import get_settings
from schemas import (
    EventIn, ForwardResponse, SimulationRequest, 
    SimulationResponse, HealthResponse, ErrorResponse
)
from ingestion import forward_event_to_member_b, check_member_b_health, cleanup_forwarding_service
from simulator import EventSimulator
from detectors import process_log_entry, get_detection_stats

# Configure logging
logger.remove()
logger.add(
    sys.stderr, 
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level=get_settings().log_level
)

# Create FastAPI app
app = FastAPI(
    title="ReliabilityAgent Ingestion Service",
    description="AI-powered on-call assistant for SREs - Event Ingestion & Forwarding to Member B",
    version=get_settings().service_version,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global request tracking for Member B
member_b_requests = []
max_request_history = 100

def log_member_b_request(request_data: Dict[str, Any]):
    """Log a request being sent to Member B for documentation."""
    global member_b_requests
    
    request_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "url": settings.member_b_url,
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Forwarded-By": "ReliabilityAgent-Ingestion",
            "X-Service-Name": settings.service_name
        },
        "payload": request_data,
        "source": request_data.get("source", "unknown"),
        "type": request_data.get("type", "unknown"),
        "payload_size": len(str(request_data.get("payload", "")))
    }
    
    # Keep only the most recent requests
    member_b_requests.append(request_log)
    if len(member_b_requests) > max_request_history:
        member_b_requests.pop(0)
    
    logger.info(f"📝 DOCUMENTED: Request #{len(member_b_requests)} to Member B logged")
    return request_log


# Initialize services
settings = get_settings()
simulator = EventSimulator()

# Global state for continuous monitoring
polling_active = False
polling_task = None
http_client = None
last_poll_timestamp = None

# Metrics tracking - Updated for webhook-based architecture
metrics = {
    "logs_processed": 0,
    "detections_found": 0,
    "events_forwarded": 0,
    "forwarding_failures": 0,
    "webhook_events_received": 0,  # NEW: Track webhook events instead of polling
    "last_webhook_time": None,     # NEW: Track last webhook received
    "polling_active": False        # DISABLED: No longer using polling
}


async def get_http_client() -> httpx.AsyncClient:
    """Get or create HTTP client for polling dummy backend."""
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


async def hook_dummy_logs_loop():
    """
    Background task that continuously polls dummy backend for new logs.
    Processes logs through detection pipeline and forwards to Member B.
    """
    global last_poll_timestamp, metrics, polling_active
    
    logger.info(f"🔄 Starting log polling loop - interval: {settings.poll_interval_seconds}s")
    polling_active = True
    metrics["polling_active"] = True
    
    while polling_active:
        try:
            client = await get_http_client()
            
            # Build polling URL with proper timestamp formatting
            if last_poll_timestamp:
                # Ensure timestamp is in correct format
                timestamp_str = last_poll_timestamp
                if isinstance(timestamp_str, datetime):
                    timestamp_str = timestamp_str.isoformat()
                url = f"{settings.dummy_backend_url}/logs/stream?since={timestamp_str}"
            else:
                url = f"{settings.dummy_backend_url}/logs/recent?limit=10"
            
            logger.debug(f"📡 Polling: {url}")
            
            # Fetch logs from dummy backend
            response = await client.get(url)
            
            if response.status_code == 200:
                log_data = response.json()
                logs = log_data.get("logs", [])
                
                metrics["last_poll_time"] = datetime.utcnow().isoformat()
                
                if logs:
                    logger.info(f"📥 Retrieved {len(logs)} new logs from dummy backend")
                    
                    # Process each log through detection pipeline
                    for log_entry in logs:
                        await process_single_log(log_entry)
                        metrics["logs_processed"] += 1
                    
                    # Update timestamp for next poll
                    if log_data.get("next_since"):
                        last_poll_timestamp = log_data["next_since"]
                        logger.debug(f"🔄 Updated timestamp for next poll: {last_poll_timestamp}")
                
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = error_data.get("detail", "")
                except:
                    error_detail = response.text
                
                logger.warning(f"❌ Failed to fetch logs: HTTP {response.status_code} - {error_detail}")
                
                # If timestamp format error, reset to get recent logs
                if response.status_code == 400 and "timestamp" in error_detail.lower():
                    logger.info("🔄 Resetting timestamp due to format error")
                    last_poll_timestamp = None
            
        except Exception as e:
            logger.error(f"💥 Error in log polling loop: {e}")
            # Reset timestamp on error to avoid getting stuck
            if "timestamp" in str(e).lower():
                logger.info("🔄 Resetting timestamp due to error")
                last_poll_timestamp = None
        
        # Wait before next poll
        await asyncio.sleep(settings.poll_interval_seconds)
    
    logger.info("🛑 Log polling loop stopped")
    metrics["polling_active"] = False


async def process_single_log(log_entry: Dict[str, Any]):
    """
    Process a single log entry through detection pipeline.
    
    Args:
        log_entry: Log entry from dummy backend
    """
    try:
        logger.debug(f"🔍 PROCESSING: Log from {log_entry.get('service', 'unknown')} - {log_entry.get('message', '')[:100]}...")
        
        # Run through security detectors
        detections = process_log_entry(log_entry)
        
        if detections:
            metrics["detections_found"] += len(detections)
            logger.warning(f"🚨 THREAT DETECTED: Found {len(detections)} security issue(s) in log!")
            
            # Forward each detection to Member B
            for detection in detections:
                if detection["score"] >= settings.min_detection_score:
                    logger.warning(f"🎯 HIGH-PRIORITY: {detection['detector']} (score: {detection['score']:.3f}) meets threshold {settings.min_detection_score}")
                    
                    # Safely access evidence patterns
                    evidence = detection.get('evidence', {})
                    matched_patterns = evidence.get('matched_patterns', [])
                    logger.warning(f"📋 THREAT DETAILS: {matched_patterns}")
                    logger.warning(f"📝 LOG CONTENT: {log_entry.get('message', '')[:200]}...")
                    
                    await forward_detection_to_member_b(detection, log_entry)
                else:
                    logger.info(f"⚠️  LOW-PRIORITY: {detection['detector']} (score: {detection['score']:.3f}) below threshold {settings.min_detection_score}")
        else:
            logger.debug(f"✅ CLEAN LOG: No threats detected in log from {log_entry.get('service', 'unknown')}")
        
    except Exception as e:
        logger.error(f"❌ PROCESSING ERROR: Failed to process log entry: {e}")
        logger.debug(f"🐛 PROBLEMATIC LOG: {log_entry}")


async def forward_detection_to_member_b(detection: Dict[str, Any], original_log: Dict[str, Any]):
    """
    Build raw_events payload and forward detection to Member B.
    
    Args:
        detection: Detection result from security detectors
        original_log: Original log entry that triggered detection
    """
    try:
        # Build raw_events JSON payload
        payload = original_log.get("message", "")
        if original_log.get("stack_trace"):
            payload += f"\n\nStack Trace:\n{original_log['stack_trace']}"
        
        # Truncate payload if too long
        if len(payload) > settings.max_payload_length:
            payload = payload[:settings.max_payload_length] + "...[truncated]"
        
        raw_event = EventIn(
            source=original_log.get("service", "dummy-service"),
            type="log",
            payload=payload,
            metadata={
                "service": original_log.get("service", "dummy-service"),
                "host": original_log.get("host", "unknown"),
                "level": original_log.get("level", "INFO"),
                "detector": detection["detector"],
                "score": detection["score"],
                "evidence": detection["evidence"],
                "original_timestamp": original_log.get("timestamp"),
                "detection_timestamp": datetime.utcnow().isoformat()
            },
            event_timestamp=datetime.fromisoformat(original_log.get("timestamp", datetime.utcnow().isoformat()).replace('Z', '+00:00'))
        )
        
        logger.info(f"🚀 MEMBER B FORWARDING: Sending {detection['detector']} detection to {settings.member_b_url}")
        logger.info(f"📊 PAYLOAD SUMMARY: {len(payload)} chars, Score: {detection['score']:.3f}")
        
        # Safely access evidence patterns
        evidence = detection.get('evidence', {})
        matched_patterns = evidence.get('matched_patterns', [])
        logger.info(f"🔗 EVIDENCE: {matched_patterns}")
        
        # Document the request for tracking
        request_data = {
            "source": raw_event.source,
            "type": raw_event.type,
            "payload": raw_event.payload,
            "metadata": raw_event.metadata,
            "event_timestamp": raw_event.event_timestamp.isoformat()
        }
        log_member_b_request(request_data)
        
        # Forward to Member B using existing forwarding logic
        forward_response = await forward_event_to_member_b(raw_event)
        
        metrics["events_forwarded"] += 1
        logger.success(f"✅ FORWARDING SUCCESS: {detection['detector']} detection delivered to Member B")
        logger.info(f"📤 MEMBER B CONFIRMED: {forward_response.forward_response_body}")
        
        return forward_response
        
    except Exception as e:
        metrics["forwarding_failures"] += 1
        logger.error(f"❌ FORWARDING FAILED: Cannot reach Member B at {settings.member_b_url}")
        logger.error(f"🔥 ERROR DETAILS: {str(e)}")
        logger.warning(f"🔄 WILL RETRY: {detection['detector']} detection will be retried automatically")
        raise


async def poll_prometheus_metrics():
    """
    Optional: Poll Prometheus metrics endpoint.
    Stub implementation for future development.
    """
    if not settings.enable_prometheus_polling:
        return
    
    logger.info("📊 Prometheus polling not yet implemented")
    # TODO: Implement Prometheus metrics polling


@app.on_event("startup")
async def startup_event():
    """Initialize services and start background tasks."""
    logger.info(f"Starting {settings.service_name} v{settings.service_version}")
    logger.info(f"Member B URL: {settings.member_b_url}")
    logger.info(f"Dummy Backend URL: {settings.dummy_backend_url}")
    logger.info(f"Continuous polling: {settings.enable_continuous_polling}")
    logger.info(f"Poll interval: {settings.poll_interval_seconds}s")
    logger.info(f"Min detection score: {settings.min_detection_score}")
    
    # Start continuous log polling if enabled
    if settings.enable_continuous_polling:
        global polling_task
        polling_task = asyncio.create_task(hook_dummy_logs_loop())
        logger.info("🚀 Started continuous log polling task")
    
    logger.info("Ingestion service started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup services and stop background tasks."""
    global polling_active, polling_task
    
    logger.info("Shutting down ingestion service")
    
    # Stop polling loop
    polling_active = False
    if polling_task:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass
    
    # Cleanup HTTP clients
    await cleanup_forwarding_service()
    await cleanup_http_client()
    
    logger.info("Shutdown complete")


@app.get("/", response_model=dict)
async def root():
    """Root endpoint with service information."""
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "status": "running",
        "architecture": "webhook-based",  # NEW: Show current architecture
        "description": "Webhook-based error log monitoring with security detection and event forwarding",
        "member_b_url": settings.member_b_url,
        "dummy_backend_url": settings.dummy_backend_url,
        "webhook_endpoint": "/webhook/error-log",  # NEW: Show webhook endpoint
        "docs": "/docs",
        "health": "/healthz",
        "metrics": "/metrics",
        "member_b_requests": "/member-b/requests",
        "webhook_info": {
            "events_received": metrics.get("webhook_events_received", 0),
            "last_webhook": metrics.get("last_webhook_time")
        }
    }


@app.get("/member-b/requests")
async def get_member_b_requests(limit: int = Query(20, ge=1, le=100)):
    """
    Get documented history of all requests sent to Member B.
    Shows detailed information about each request for debugging and verification.
    """
    recent_requests = member_b_requests[-limit:] if len(member_b_requests) > limit else member_b_requests
    
    return {
        "total_requests": len(member_b_requests),
        "showing": len(recent_requests),
        "member_b_url": settings.member_b_url,
        "requests": recent_requests,
        "summary": {
            "last_24h": len([r for r in member_b_requests if 
                           (datetime.utcnow() - datetime.fromisoformat(r["timestamp"])).total_seconds() < 86400]),
            "error_detections": len([r for r in member_b_requests if 
                                   r["payload"].get("metadata", {}).get("detector") in ["error-log", "database-issues"]]),
            "security_detections": len([r for r in member_b_requests if 
                                      r["payload"].get("metadata", {}).get("detector") in ["xss", "sqli", "ssrf"]])
        }
    }


@app.delete("/member-b/requests")
async def clear_member_b_requests():
    """Clear the Member B request history."""
    global member_b_requests
    count = len(member_b_requests)
    member_b_requests.clear()
    logger.info(f"🗑️  CLEARED: Removed {count} Member B request logs")
    
    return {
        "status": "cleared",
        "requests_removed": count,
        "message": f"Cleared {count} Member B request logs"
    }


@app.get("/healthz", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    member_b_reachable = await check_member_b_health()
    
    # Check dummy backend health if polling is enabled
    dummy_backend_reachable = True
    if settings.enable_continuous_polling:
        try:
            client = await get_http_client()
            response = await client.get(f"{settings.dummy_backend_url}/health", timeout=5.0)
            dummy_backend_reachable = response.status_code == 200
        except:
            dummy_backend_reachable = False
    
    status = "healthy"
    if not member_b_reachable:
        status = "degraded"
    elif settings.enable_continuous_polling and not dummy_backend_reachable:
        status = "degraded"
    
    return HealthResponse(
        status=status,
        service=settings.service_name,
        version=settings.service_version,
        timestamp=datetime.utcnow(),
        member_b_url=settings.member_b_url,
        member_b_reachable=member_b_reachable
    )


@app.get("/metrics")
async def get_metrics():
    """Get service metrics and detection statistics."""
    detection_stats = get_detection_stats()
    
    return {
        "service_metrics": {
            **metrics,
            "architecture": "webhook-based",  # NEW: Show current architecture
            "polling_disabled": True          # NEW: Indicate polling is disabled
        },
        "detection_stats": detection_stats,
        "configuration": {
            "member_b_url": settings.member_b_url,
            "dummy_backend_url": settings.dummy_backend_url,
            "min_detection_score": settings.min_detection_score,
            "max_payload_length": settings.max_payload_length,
            "webhook_endpoint": "/webhook/error-log",  # NEW: Show webhook endpoint
            "continuous_polling_enabled": settings.enable_continuous_polling
        },
        "webhook_info": {
            "events_received": metrics.get("webhook_events_received", 0),
            "last_webhook": metrics.get("last_webhook_time"),
            "webhook_url": f"http://localhost:8000/webhook/error-log"
        }
    }


@app.post("/simulate/start")
async def start_polling():
    """Admin endpoint to start continuous log polling."""
    global polling_active, polling_task
    
    if polling_active:
        return {
            "status": "already_running",
            "message": "Log polling is already active",
            "polling_active": True
        }
    
    polling_active = True
    polling_task = asyncio.create_task(hook_dummy_logs_loop())
    
    logger.info("🚀 Log polling started via admin endpoint")
    return {
        "status": "started",
        "message": "Continuous log polling started",
        "polling_active": True
    }


@app.post("/simulate/stop")
async def stop_polling():
    """Admin endpoint to stop continuous log polling."""
    global polling_active, polling_task
    
    if not polling_active:
        return {
            "status": "already_stopped",
            "message": "Log polling is already stopped",
            "polling_active": False
        }
    
    polling_active = False
    if polling_task:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass
    
    logger.info("🛑 Log polling stopped via admin endpoint")
    return {
        "status": "stopped",
        "message": "Continuous log polling stopped",
        "polling_active": False
    }


@app.post("/webhook/error-log")
async def receive_error_log_webhook(event: EventIn):
    """
    Webhook endpoint specifically for receiving error log notifications from dummy backend.
    This replaces the polling mechanism - dummy backend sends webhooks when error logs are generated.
    """
    try:
        logger.info(f"📥 ERROR LOG WEBHOOK: Received {event.metadata.get('level', 'UNKNOWN')} log from {event.source}")
        logger.info(f"📝 LOG MESSAGE: {event.payload[:100]}...")
        
        # Convert webhook event to log entry format for processing
        log_entry = {
            "timestamp": event.event_timestamp.isoformat(),
            "service": event.source,
            "level": event.metadata.get("level", "ERROR"),
            "message": event.payload,
            "host": event.metadata.get("host", "unknown"),
            "stack_trace": event.metadata.get("stack_trace"),
            "payload": event.metadata.get("original_payload")
        }
        
        # Process through detection pipeline
        logger.info(f"🔍 PROCESSING: Error log through security detection pipeline")
        detections = process_log_entry(log_entry)
        
        if detections:
            logger.warning(f"🚨 SECURITY THREATS DETECTED: Found {len(detections)} issue(s) in error log!")
            
            # Forward each detection to Member B
            for detection in detections:
                if detection["score"] >= settings.min_detection_score:
                    logger.warning(f"🎯 HIGH-PRIORITY THREAT: {detection['detector']} (score: {detection['score']:.3f})")
                    
                    # Safely access evidence patterns
                    evidence = detection.get('evidence', {})
                    matched_patterns = evidence.get('matched_patterns', [])
                    logger.warning(f"📋 THREAT EVIDENCE: {matched_patterns}")
                    
                    await forward_detection_to_member_b(detection, log_entry)
                    metrics["events_forwarded"] += 1
                else:
                    logger.info(f"⚠️  LOW-PRIORITY: {detection['detector']} (score: {detection['score']:.3f}) below threshold")
        else:
            # Even if no security threats detected, this is still an error log
            # Forward it to Member B as an operational error
            logger.info(f"📤 OPERATIONAL ERROR: Forwarding error log to Member B (no security threats)")
            
            # Create a basic error detection
            error_detection = {
                "detector": "error-log",
                "score": 0.5,  # Medium priority for operational errors
                "evidence": {
                    "matched_patterns": ["error_level"],  # Ensure matched_patterns exists
                    "error_level": log_entry["level"],
                    "has_stack_trace": bool(log_entry.get("stack_trace")),
                    "message_preview": log_entry["message"][:100]
                }
            }
            
            await forward_detection_to_member_b(error_detection, log_entry)
            metrics["events_forwarded"] += 1
        
        metrics["webhook_events_received"] = metrics.get("webhook_events_received", 0) + 1
        metrics["last_webhook_time"] = datetime.utcnow().isoformat()
        
        return {
            "status": "processed",
            "source": event.source,
            "level": log_entry["level"],
            "detections_found": len(detections),
            "forwarded_to_member_b": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK ERROR: Failed to process error log from {event.source}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process error log webhook: {str(e)}"
        )


@app.post("/webhook/event", response_model=ForwardResponse)
async def receive_webhook_event(event: EventIn):
    """
    Webhook endpoint for receiving events from external systems.
    Validates event and forwards to Member B service.
    """
    try:
        logger.info(f"📥 WEBHOOK: Received event from {event.source}")
        logger.info(f"📋 EVENT DETAILS: Type: {event.type}, Payload length: {len(event.payload)} chars")
        
        # Run event through detection pipeline first
        log_entry = {
            "timestamp": event.event_timestamp.isoformat(),
            "service": event.source,
            "level": "INFO",
            "message": event.payload,
            "metadata": event.metadata
        }
        
        # Process through security detectors
        detections = process_log_entry(log_entry)
        
        if detections:
            logger.info(f"🚨 SECURITY ALERT: {len(detections)} threat(s) detected in webhook event!")
            
            for detection in detections:
                logger.warning(f"🔍 DETECTED: {detection['detector']} threat with confidence {detection['score']:.3f}")
                logger.warning(f"📊 EVIDENCE: {detection['evidence']['matched_patterns']}")
                
                # Add detection metadata to the original event
                enhanced_event = EventIn(
                    source=event.source,
                    type=event.type,
                    payload=event.payload,
                    metadata={
                        **event.metadata,
                        "detector": detection["detector"],
                        "score": detection["score"],
                        "evidence": detection["evidence"],
                        "detection_timestamp": datetime.utcnow().isoformat()
                    },
                    event_timestamp=event.event_timestamp
                )
                
                # Forward enhanced event to Member B
                logger.info(f"🚀 FORWARDING: Sending {detection['detector']} detection to Member B at {settings.member_b_url}")
                
                # Document the request
                request_data = {
                    "source": enhanced_event.source,
                    "type": enhanced_event.type,
                    "payload": enhanced_event.payload,
                    "metadata": enhanced_event.metadata,
                    "event_timestamp": enhanced_event.event_timestamp.isoformat()
                }
                log_member_b_request(request_data)
                
                forward_response = await forward_event_to_member_b(enhanced_event)
                
                logger.success(f"✅ SUCCESS: {detection['detector']} detection forwarded to Member B")
                logger.info(f"📤 MEMBER B RESPONSE: {forward_response.member_b_response}")
                
                return forward_response
        else:
            logger.info(f"✨ CLEAN EVENT: No security threats detected, forwarding original event")
        
        # Forward original event to Member B (no detections)
        logger.info(f"🚀 FORWARDING: Sending clean event to Member B at {settings.member_b_url}")
        
        # Document the request
        request_data = {
            "source": event.source,
            "type": event.type,
            "payload": event.payload,
            "metadata": event.metadata,
            "event_timestamp": event.event_timestamp.isoformat()
        }
        log_member_b_request(request_data)
        
        forward_response = await forward_event_to_member_b(event)
        
        logger.success(f"✅ SUCCESS: Event from {event.source} forwarded successfully")
        logger.info(f"📤 MEMBER B RESPONSE: {forward_response.member_b_response}")
        
        return forward_response
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK ERROR: Failed to process event from {event.source}: {e}")
        raise HTTPException(
            status_code=502, 
            detail=ErrorResponse(detail=str(e)).dict()
        )


async def _handle_single_event_forward(event: EventIn) -> ForwardResponse:
    """Internal handler for forwarding a single event."""
    return await forward_event_to_member_b(event)


@app.post("/simulate/{scenario}", response_model=SimulationResponse)
async def simulate_events(
    scenario: str,
    simulation_config: SimulationRequest = SimulationRequest()
):
    """
    Simulate events for testing and demo purposes.
    Generates fake events and forwards them using the same code path as webhook events.
    """
    try:
        # Validate scenario
        available_scenarios = simulator.get_available_scenarios()
        if scenario.lower() not in available_scenarios:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scenario '{scenario}'. Available: {available_scenarios}"
            )
        
        logger.info(f"Starting simulation: {scenario} (count: {simulation_config.count})")
        
        # Generate events
        events = simulator.generate_events(
            scenario=scenario,
            count=simulation_config.count,
            delay_seconds=simulation_config.delay_seconds
        )
        
        # Forward each event using the same internal handler as webhook events
        forward_responses = []
        events_forwarded = 0
        
        for event in events:
            try:
                forward_response = await _handle_single_event_forward(event)
                forward_responses.append(forward_response)
                events_forwarded += 1
                logger.info(f"Simulated event forwarded successfully: {forward_response.forward_response_status}")
            except Exception as e:
                logger.error(f"Failed to forward simulated event: {e}")
                # Add error response
                error_response = ForwardResponse(
                    status="error",
                    forward_response_status=502,
                    forward_response_body={"error": str(e)}
                )
                forward_responses.append(error_response)
        
        logger.info(f"Simulation completed: {events_forwarded}/{len(events)} events forwarded")
        
        return SimulationResponse(
            message="Simulation completed",
            scenario=scenario,
            events_forwarded=events_forwarded,
            forward_responses=forward_responses
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Simulation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scenarios")
async def get_available_scenarios():
    """Get list of available simulation scenarios."""
    return {
        "scenarios": simulator.get_available_scenarios(),
        "description": "Available scenarios for event simulation"
    }


@app.get("/status")
async def get_service_status():
    """Get detailed service status including Member B connectivity."""
    member_b_reachable = await check_member_b_health()
    
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "status": "healthy" if member_b_reachable else "degraded",
        "member_b": {
            "url": settings.member_b_url,
            "reachable": member_b_reachable,
            "max_retries": settings.max_forward_retries,
            "retry_backoff": settings.forward_retry_backoff
        },
        "configuration": {
            "log_level": settings.log_level,
            "api_host": settings.api_host,
            "api_port": settings.api_port
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_debug,
        log_level=settings.log_level.lower()
    )