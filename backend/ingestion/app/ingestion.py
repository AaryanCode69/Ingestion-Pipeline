"""
Core ingestion logic for forwarding events to Member B with retries.
"""
import asyncio
import json
from typing import Dict, Any, Union, Tuple
import httpx
from loguru import logger

from schemas import EventIn, ForwardResponse, ErrorResponse
from config import get_settings

settings = get_settings()


class ForwardingService:
    """Service for forwarding events to Member B with retry logic."""
    
    def __init__(self):
        self.settings = settings
        self.client = None
    
    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=30.0)
        return self.client
    
    async def close_client(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    async def forward_event(self, event_data: EventIn) -> ForwardResponse:
        """
        Forward an event to Member B with exponential backoff retry.
        
        Args:
            event_data: Validated event data
            
        Returns:
            ForwardResponse with status and Member B response
            
        Raises:
            Exception: If forwarding fails after all retries
        """
        # Convert EventIn to dict for forwarding (matching raw_events schema exactly)
        forward_payload = {
            "source": event_data.source,
            "type": event_data.type,
            "payload": event_data.payload,
            "metadata": event_data.metadata,
            "event_timestamp": event_data.event_timestamp.isoformat()
        }
        
        logger.info(f"🚀 MEMBER B REQUEST: Forwarding event from {event_data.source} to {self.settings.member_b_url}")
        logger.info(f"📋 REQUEST PAYLOAD: {json.dumps(forward_payload, indent=2)}")
        
        last_error = None
        
        for attempt in range(self.settings.max_forward_retries + 1):
            try:
                client = await self.get_client()
                
                logger.info(f"🔄 ATTEMPT {attempt + 1}: POST {self.settings.member_b_url}")
                logger.info(f"📤 HEADERS: Content-Type: application/json, X-Forwarded-By: ReliabilityAgent-Ingestion, X-Service-Name: {self.settings.service_name}")
                
                response = await client.post(
                    self.settings.member_b_url,
                    json=forward_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Forwarded-By": "ReliabilityAgent-Ingestion",
                        "X-Service-Name": self.settings.service_name
                    }
                )
                
                # Try to parse response as JSON, fallback to text
                try:
                    response_body = response.json()
                except (json.JSONDecodeError, ValueError):
                    response_body = response.text
                
                logger.success(f"✅ MEMBER B RESPONSE: Status {response.status_code}")
                logger.info(f"📥 RESPONSE BODY: {json.dumps(response_body, indent=2) if isinstance(response_body, dict) else response_body}")
                
                return ForwardResponse(
                    status="forwarded",
                    forward_response_status=response.status_code,
                    forward_response_body=response_body,
                    member_b_response=response_body
                )
                
            except httpx.RequestError as e:
                last_error = e
                logger.error(f"❌ ATTEMPT {attempt + 1} FAILED: Request error: {e}")
                
                # Don't retry if we've exhausted attempts
                if attempt >= self.settings.max_forward_retries:
                    break
                
                # Exponential backoff: base_delay * (2 ^ attempt)
                delay = self.settings.forward_retry_backoff * (2 ** attempt)
                logger.warning(f"⏰ RETRY DELAY: Waiting {delay} seconds before attempt {attempt + 2}...")
                await asyncio.sleep(delay)
            
            except Exception as e:
                last_error = e
                logger.error(f"💥 ATTEMPT {attempt + 1} FAILED: Unexpected error: {e}")
                break
        
        # All retries failed
        error_msg = f"💀 MEMBER B UNREACHABLE: Failed to forward event after {self.settings.max_forward_retries + 1} attempts. Last error: {last_error}"
        logger.error(error_msg)
        raise Exception(error_msg)
    
    async def health_check_member_b(self) -> bool:
        """
        Check if Member B is reachable.
        
        Returns:
            True if Member B responds to requests, False otherwise
        """
        try:
            client = await self.get_client()
            
            # Try a simple GET to the base URL or health endpoint
            base_url = self.settings.member_b_url.rsplit('/', 1)[0]  # Remove /raw_events
            health_urls = [f"{base_url}/health", f"{base_url}/", base_url]
            
            for url in health_urls:
                try:
                    response = await client.get(url, timeout=5.0)
                    if response.status_code < 500:  # Any non-server error means it's reachable
                        logger.info(f"Member B health check successful at {url}")
                        return True
                except httpx.RequestError:
                    continue
            
            logger.warning("Member B health check failed for all endpoints")
            return False
            
        except Exception as e:
            logger.error(f"Member B health check error: {e}")
            return False


# Global forwarding service instance
forwarding_service = ForwardingService()


async def forward_event_to_member_b(event_data: EventIn) -> ForwardResponse:
    """
    Forward event to Member B. This is the main entry point for event forwarding.
    
    Args:
        event_data: Validated event data
        
    Returns:
        ForwardResponse
        
    Raises:
        Exception: If forwarding fails after retries
    """
    return await forwarding_service.forward_event(event_data)


async def check_member_b_health() -> bool:
    """Check Member B health."""
    return await forwarding_service.health_check_member_b()


async def cleanup_forwarding_service():
    """Cleanup forwarding service resources."""
    await forwarding_service.close_client()