"""
Integration tests for the ReliabilityAgent continuous monitoring system.
Tests the complete pipeline from log generation to detection to forwarding.
"""
import pytest
import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import httpx
import respx

from backend.ingestion.app.main import app
from backend.ingestion.app.config import get_settings
from backend.ingestion.app.detectors import process_log_entry


class TestContinuousMonitoringIntegration:
    """Integration tests for continuous monitoring pipeline."""
    
    def setup_method(self):
        self.client = TestClient(app)
        self.settings = get_settings()
    
    def test_healthz_endpoint(self):
        """Test health check endpoint."""
        response = self.client.get("/healthz")
        assert response.status_code == 200
        
        data = response.json()
        assert data["service"] == "ingestion"
        assert "status" in data
        assert "timestamp" in data
    
    def test_metrics_endpoint(self):
        """Test metrics endpoint returns proper structure."""
        response = self.client.get("/metrics")
        assert response.status_code == 200
        
        data = response.json()
        assert "service_metrics" in data
        assert "detection_stats" in data
        assert "configuration" in data
        
        # Check required metrics fields
        service_metrics = data["service_metrics"]
        assert "logs_processed" in service_metrics
        assert "detections_found" in service_metrics
        assert "events_forwarded" in service_metrics
    
    def test_admin_start_stop_polling(self):
        """Test admin endpoints for starting/stopping polling."""
        # Test start
        response = self.client.post("/simulate/start")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["started", "already_running"]
        
        # Test stop
        response = self.client.post("/simulate/stop")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["stopped", "already_stopped"]
    
    @respx.mock
    def test_webhook_event_forwarding(self):
        """Test that webhook events are properly forwarded to Member B."""
        # Mock Member B endpoint
        member_b_mock = respx.post(self.settings.member_b_url).mock(
            return_value=httpx.Response(200, json={"status": "received", "id": "test-123"})
        )
        
        # Send test event to webhook
        test_event = {
            "source": "test-service",
            "type": "log",
            "payload": "Test log message",
            "metadata": {"test": True},
            "event_timestamp": datetime.utcnow().isoformat()
        }
        
        response = self.client.post("/webhook/event", json=test_event)
        assert response.status_code == 200
        
        # Verify Member B was called
        assert member_b_mock.called
        
        # Check response structure
        data = response.json()
        assert data["status"] == "forwarded"
        assert data["member_b_response"]["status"] == "received"


class TestLogProcessingPipeline:
    """Test the complete log processing pipeline."""
    
    @pytest.mark.asyncio
    async def test_process_malicious_log_xss(self):
        """Test processing of XSS-containing log."""
        from backend.ingestion.app.main import process_single_log
        
        malicious_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "web-service",
            "level": "WARN",
            "message": "User input contained: <script>alert('XSS')</script>",
            "host": "web-01"
        }
        
        with patch('backend.ingestion.app.main.forward_detection_to_member_b') as mock_forward:
            mock_forward.return_value = {"status": "forwarded"}
            
            await process_single_log(malicious_log)
            
            # Verify detection was forwarded
            assert mock_forward.called
            args, kwargs = mock_forward.call_args
            detection = args[0]
            
            assert detection["detector"] == "XSS"
            assert detection["score"] >= 0.45
            assert "script_tag" in detection["evidence"]["matched_patterns"]
    
    @pytest.mark.asyncio
    async def test_process_malicious_log_sqli(self):
        """Test processing of SQLi-containing log."""
        from backend.ingestion.app.main import process_single_log
        
        malicious_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "api-service",
            "level": "ERROR",
            "message": "Login attempt with: username=admin' OR 1=1 --",
            "host": "api-01"
        }
        
        with patch('backend.ingestion.app.main.forward_detection_to_member_b') as mock_forward:
            mock_forward.return_value = {"status": "forwarded"}
            
            await process_single_log(malicious_log)
            
            # Verify detection was forwarded
            assert mock_forward.called
            args, kwargs = mock_forward.call_args
            detection = args[0]
            
            assert detection["detector"] == "SQLi"
            assert detection["score"] >= 0.6
            assert "or_equals" in detection["evidence"]["matched_patterns"]
    
    @pytest.mark.asyncio
    async def test_process_database_timeout_log(self):
        """Test processing of database timeout log."""
        from backend.ingestion.app.main import process_single_log
        
        timeout_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "db-service",
            "level": "ERROR",
            "message": "Database connection timed out after 3500ms",
            "host": "db-01",
            "stack_trace": "Full timeout stack trace here..."
        }
        
        with patch('backend.ingestion.app.main.forward_detection_to_member_b') as mock_forward:
            mock_forward.return_value = {"status": "forwarded"}
            
            await process_single_log(timeout_log)
            
            # Verify detection was forwarded
            assert mock_forward.called
            args, kwargs = mock_forward.call_args
            detection = args[0]
            
            assert detection["detector"] == "DB_TIMEOUT"
            assert detection["evidence"]["extracted_latency_ms"] == 3500.0
    
    @pytest.mark.asyncio
    async def test_process_benign_log_no_forwarding(self):
        """Test that benign logs don't trigger forwarding."""
        from backend.ingestion.app.main import process_single_log
        
        benign_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "auth-service",
            "level": "INFO",
            "message": "User successfully authenticated",
            "host": "auth-01"
        }
        
        with patch('backend.ingestion.app.main.forward_detection_to_member_b') as mock_forward:
            await process_single_log(benign_log)
            
            # Verify no forwarding occurred
            assert not mock_forward.called


class TestMemberBForwarding:
    """Test forwarding logic to Member B."""
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_forward_detection_to_member_b(self):
        """Test forwarding detection results to Member B."""
        from backend.ingestion.app.main import forward_detection_to_member_b
        
        # Mock Member B response
        member_b_mock = respx.post(self.settings.member_b_url).mock(
            return_value=httpx.Response(200, json={"status": "received", "event_id": "evt-123"})
        )
        
        detection = {
            "detector": "XSS",
            "score": 0.85,
            "evidence": {
                "matched_patterns": ["script_tag"],
                "content_snippet": "<script>alert(1)</script>",
                "detector": "XSS"
            }
        }
        
        original_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "web-service",
            "level": "WARN",
            "message": "XSS detected in user input: <script>alert(1)</script>",
            "host": "web-01"
        }
        
        response = await forward_detection_to_member_b(detection, original_log)
        
        # Verify Member B was called
        assert member_b_mock.called
        
        # Check request payload
        request = member_b_mock.calls[0].request
        payload = json.loads(request.content)
        
        assert payload["source"] == "web-service"
        assert payload["type"] == "log"
        assert "XSS detected" in payload["payload"]
        assert payload["metadata"]["detector"] == "XSS"
        assert payload["metadata"]["score"] == 0.85
        assert "evidence" in payload["metadata"]
        
        # Check headers
        assert request.headers["X-Forwarded-By"] == "ReliabilityAgent-Ingestion"
        assert request.headers["X-Service-Name"] == "ingestion"
    
    @pytest.mark.asyncio
    async def test_payload_truncation(self):
        """Test that long payloads are properly truncated."""
        from backend.ingestion.app.main import forward_detection_to_member_b
        
        long_message = "A" * 3000  # Longer than max_payload_length
        
        detection = {
            "detector": "XSS",
            "score": 0.7,
            "evidence": {"matched_patterns": ["script_tag"]}
        }
        
        original_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "test-service",
            "message": long_message,
            "stack_trace": "B" * 1000
        }
        
        with patch('backend.ingestion.app.main.forward_event_to_member_b') as mock_forward:
            mock_forward.return_value = {"status": "forwarded"}
            
            await forward_detection_to_member_b(detection, original_log)
            
            # Verify forwarding was called
            assert mock_forward.called
            
            # Check that payload was truncated
            args, kwargs = mock_forward.call_args
            event = args[0]
            
            assert len(event.payload) <= self.settings.max_payload_length + 20  # Account for truncation marker
            assert "...[truncated]" in event.payload


class TestDummyBackendIntegration:
    """Test integration with dummy backend log streaming."""
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_poll_dummy_backend_logs(self):
        """Test polling logs from dummy backend."""
        from backend.ingestion.app.main import hook_dummy_logs_loop
        
        # Mock dummy backend responses
        dummy_logs = {
            "logs": [
                {
                    "timestamp": "2025-09-21T12:00:00Z",
                    "service": "dummy-service",
                    "level": "WARN",
                    "message": "Test XSS: <script>alert(1)</script>",
                    "host": "dummy-host"
                }
            ],
            "total_count": 1,
            "next_since": "2025-09-21T12:00:01Z"
        }
        
        dummy_backend_mock = respx.get(f"{self.settings.dummy_backend_url}/logs/recent").mock(
            return_value=httpx.Response(200, json=dummy_logs)
        )
        
        # Mock Member B forwarding
        member_b_mock = respx.post(self.settings.member_b_url).mock(
            return_value=httpx.Response(200, json={"status": "received"})
        )
        
        # Run one iteration of the polling loop
        with patch('backend.ingestion.app.main.polling_active', True), \
             patch('backend.ingestion.app.main.asyncio.sleep', side_effect=StopAsyncIteration):
            
            try:
                await hook_dummy_logs_loop()
            except StopAsyncIteration:
                pass  # Expected to break the loop
        
        # Verify dummy backend was polled
        assert dummy_backend_mock.called
        
        # Verify Member B received the detection
        assert member_b_mock.called


class TestErrorHandling:
    """Test error handling in the monitoring pipeline."""
    
    @pytest.mark.asyncio
    async def test_detector_error_handling(self):
        """Test that detector errors don't crash the pipeline."""
        from backend.ingestion.app.main import process_single_log
        
        # Create a log that might cause issues
        problematic_log = {
            "timestamp": None,  # Invalid timestamp
            "message": None,    # None message
            "level": "ERROR"
        }
        
        # Should not raise an exception
        await process_single_log(problematic_log)
    
    @pytest.mark.asyncio
    @respx.mock 
    async def test_member_b_unavailable_handling(self):
        """Test handling when Member B is unavailable."""
        from backend.ingestion.app.main import forward_detection_to_member_b
        
        # Mock Member B as unavailable
        respx.post(self.settings.member_b_url).mock(
            return_value=httpx.Response(503, text="Service Unavailable")
        )
        
        detection = {
            "detector": "XSS",
            "score": 0.8,
            "evidence": {"matched_patterns": ["script_tag"]}
        }
        
        original_log = {
            "timestamp": "2025-09-21T12:00:00Z",
            "service": "test-service",
            "message": "Test message"
        }
        
        # Should handle the error gracefully
        with pytest.raises(Exception):
            await forward_detection_to_member_b(detection, original_log)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])