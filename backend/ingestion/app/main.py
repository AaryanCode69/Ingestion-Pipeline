"""
FastAPI application for the ReliabilityAgent ingestion service.
Handles webhook events and forwards them to Member B service.
"""
import asyncio
from datetime import datetime
from typing import List
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
import sys

from .config import get_settings
from .schemas import (
    EventIn, ForwardResponse, SimulationRequest, 
    SimulationResponse, HealthResponse, ErrorResponse
)
from .ingestion import forward_event_to_member_b, check_member_b_health, cleanup_forwarding_service
from .simulator import EventSimulator

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

# Initialize services
settings = get_settings()
simulator = EventSimulator()


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info(f"Starting {settings.service_name} v{settings.service_version}")
    logger.info(f"Member B URL: {settings.member_b_url}")
    logger.info(f"Max forward retries: {settings.max_forward_retries}")
    logger.info("Ingestion service started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down ingestion service")
    await cleanup_forwarding_service()


@app.get("/", response_model=dict)
async def root():
    """Root endpoint with service information."""
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "status": "running",
        "description": "Event ingestion and forwarding to Member B",
        "member_b_url": settings.member_b_url,
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    member_b_reachable = await check_member_b_health()
    
    status = "healthy" if member_b_reachable else "degraded"
    
    return HealthResponse(
        status=status,
        service=settings.service_name,
        version=settings.service_version,
        timestamp=datetime.utcnow(),
        member_b_url=settings.member_b_url,
        member_b_reachable=member_b_reachable
    )


@app.post("/webhook/event", response_model=ForwardResponse)
async def receive_webhook_event(event: EventIn):
    """
    Webhook endpoint for receiving events from external systems.
    Validates event and forwards to Member B service.
    """
    try:
        logger.info(f"Received webhook event from {event.source}")
        
        # Forward event to Member B
        forward_response = await forward_event_to_member_b(event)
        
        logger.info(f"Event from {event.source} forwarded successfully")
        return forward_response
        
    except Exception as e:
        logger.error(f"Failed to forward webhook event: {e}")
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