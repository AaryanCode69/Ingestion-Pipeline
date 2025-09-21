"""
Unit tests for security detectors in the ReliabilityAgent ingestion service.
Tests XSS, SQLi, SSRF, and Database timeout detection logic.
"""
import pytest
from datetime import datetime
from backend.ingestion.app.detectors import (
    XSSDetector, SQLiDetector, SSRFDetector, DatabaseIssuesDetector,
    DetectionEngine, process_log_entry
)


class TestXSSDetector:
    """Test cases for XSS detection."""
    
    def setup_method(self):
        self.detector = XSSDetector()
    
    def test_basic_script_tag_detection(self):
        """Test detection of basic script tags."""
        log_entry = {
            "message": "User input: <script>alert('XSS')</script>",
            "timestamp": "2025-09-21T12:00:00Z",
            "level": "WARN"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.45
        assert "script_tag" in evidence["matched_patterns"]
        assert evidence["detector"] == "XSS"
    
    def test_event_handler_detection(self):
        """Test detection of event handlers."""
        log_entry = {
            "message": "Suspicious payload: <img src=x onerror=alert(1)>",
            "timestamp": "2025-09-21T12:00:00Z"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.6
        assert "script_events" in evidence["matched_patterns"]
    
    def test_obfuscated_script_detection(self):
        """Test detection of obfuscated script tags."""
        log_entry = {
            "message": "Obfuscated: < s c r i p t >alert(1)< / s c r i p t >",
            "stack_trace": "Some stack trace here"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.65
        assert "obfuscated_script" in evidence["matched_patterns"]
    
    def test_multiple_xss_patterns(self):
        """Test detection with multiple XSS patterns."""
        log_entry = {
            "message": "Multiple threats: <script>document.cookie</script> and onerror=alert(1)",
            "payload": "eval(malicious_code)"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert len(evidence["matched_patterns"]) >= 3
        assert score <= 1.0  # Score should be capped at 1.0
    
    def test_benign_content_no_detection(self):
        """Test that benign content is not detected."""
        log_entry = {
            "message": "Normal user login successful",
            "timestamp": "2025-09-21T12:00:00Z"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is False
        assert score == 0.0
        assert evidence["matched_patterns"] == []


class TestSQLiDetector:
    """Test cases for SQL injection detection."""
    
    def setup_method(self):
        self.detector = SQLiDetector()
    
    def test_union_select_detection(self):
        """Test detection of UNION SELECT attacks."""
        log_entry = {
            "message": "Query: SELECT * FROM users UNION SELECT password FROM admin",
            "level": "ERROR"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.6
        assert "union_select" in evidence["matched_patterns"]
    
    def test_or_equals_bypass(self):
        """Test detection of OR 1=1 bypass."""
        log_entry = {
            "message": "Login attempt: username=admin' OR 1=1 --",
            "payload": "Suspicious login data"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.6
        assert "or_equals" in evidence["matched_patterns"]
    
    def test_drop_table_attack(self):
        """Test detection of DROP TABLE attacks."""
        log_entry = {
            "message": "Malicious input: '; DROP TABLE users; --",
            "stack_trace": "SQL error occurred"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.8
        assert "drop_table" in evidence["matched_patterns"]
    
    def test_comment_bypass(self):
        """Test detection of comment-based bypasses."""
        log_entry = {
            "message": "Query: SELECT * FROM users WHERE id=1 -- AND role='admin'"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert "comment_bypass" in evidence["matched_patterns"]
    
    def test_information_schema_access(self):
        """Test detection of information schema queries."""
        log_entry = {
            "message": "Query: SELECT table_name FROM INFORMATION_SCHEMA.tables"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert "information_schema" in evidence["matched_patterns"]


class TestSSRFDetector:
    """Test cases for SSRF detection."""
    
    def setup_method(self):
        self.detector = SSRFDetector()
    
    def test_aws_metadata_detection(self):
        """Test detection of AWS metadata service access."""
        log_entry = {
            "message": "Outbound request to: http://169.254.169.254/latest/meta-data/",
            "level": "WARN"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.9
        assert "aws_metadata_path" in evidence["matched_patterns"]
    
    def test_localhost_access(self):
        """Test detection of localhost access."""
        log_entry = {
            "message": "Request to internal service: http://localhost:8080/admin"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert "localhost" in evidence["matched_patterns"]
    
    def test_file_protocol_detection(self):
        """Test detection of file protocol usage."""
        log_entry = {
            "message": "Trying to access: file:///etc/passwd",
            "payload": "Suspicious file access"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.7
        assert "file_protocol" in evidence["matched_patterns"]
    
    def test_curl_internal_ip(self):
        """Test detection of curl to internal IPs."""
        log_entry = {
            "message": "Command executed: curl http://127.0.0.1:9200/_cluster/health"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert "curl_internal" in evidence["matched_patterns"]


class TestDatabaseIssuesDetector:
    """Test cases for database issues detection."""
    
    def setup_method(self):
        self.detector = DatabaseIssuesDetector()
    
    def test_timeout_detection(self):
        """Test detection of database timeouts."""
        log_entry = {
            "message": "Database connection timed out after 5000ms",
            "level": "ERROR",
            "stack_trace": "Timeout error stack trace"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.7
        assert "connection_timeout" in evidence["matched_patterns"]
    
    def test_deadlock_detection(self):
        """Test detection of database deadlocks."""
        log_entry = {
            "message": "ERROR: deadlock detected in transaction",
            "stack_trace": "Full deadlock stack trace here"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.8
        assert "deadlock" in evidence["matched_patterns"]
    
    def test_latency_extraction(self):
        """Test extraction and scoring of latency values."""
        log_entry = {
            "message": "Query completed with latency=3500ms",
            "level": "WARN"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert evidence["extracted_latency_ms"] == 3500.0
        assert score >= 0.6  # Should score high for >2s latency
    
    def test_explicit_db_timeout(self):
        """Test detection of explicit DB_TIMEOUT."""
        log_entry = {
            "message": "DB_TIMEOUT: Query exceeded maximum execution time",
            "metadata": {"query_time": "8000ms"}
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert score >= 0.8
        assert "db_timeout_explicit" in evidence["matched_patterns"]
    
    def test_connection_pool_exhaustion(self):
        """Test detection of connection pool issues."""
        log_entry = {
            "message": "Database connection pool exhausted - no available connections"
        }
        
        detected, score, evidence = self.detector.detect(log_entry)
        
        assert detected is True
        assert "connection_pool" in evidence["matched_patterns"]


class TestDetectionEngine:
    """Test cases for the main detection engine."""
    
    def setup_method(self):
        self.engine = DetectionEngine()
    
    def test_multiple_detections_in_single_log(self):
        """Test that multiple detections can be found in one log entry."""
        log_entry = {
            "message": "XSS and SQLi: <script>alert(1)</script> and ' OR 1=1 --",
            "timestamp": "2025-09-21T12:00:00Z",
            "level": "ERROR"
        }
        
        detections = self.engine.process_log_entry(log_entry)
        
        assert len(detections) >= 2
        detector_names = [d["detector"] for d in detections]
        assert "XSS" in detector_names
        assert "SQLi" in detector_names
    
    def test_benign_log_no_detections(self):
        """Test that benign logs produce no detections."""
        log_entry = {
            "message": "User successfully logged in",
            "timestamp": "2025-09-21T12:00:00Z",
            "level": "INFO",
            "service": "auth-service"
        }
        
        detections = self.engine.process_log_entry(log_entry)
        
        assert len(detections) == 0
    
    def test_process_log_entry_function(self):
        """Test the module-level process_log_entry function."""
        log_entry = {
            "message": "SSRF attempt: curl http://169.254.169.254/latest/meta-data/",
            "timestamp": "2025-09-21T12:00:00Z",
            "level": "WARN"
        }
        
        detections = process_log_entry(log_entry)
        
        assert len(detections) == 1
        assert detections[0]["detector"] == "SSRF"
        assert detections[0]["score"] >= 0.9
    
    def test_detection_stats(self):
        """Test that detection statistics are properly tracked."""
        from backend.ingestion.app.detectors import get_detection_stats
        
        # Process some logs to generate stats
        xss_log = {"message": "<script>alert(1)</script>"}
        sqli_log = {"message": "' OR 1=1 --"}
        
        process_log_entry(xss_log)
        process_log_entry(sqli_log)
        
        stats = get_detection_stats()
        
        assert "total_processed" in stats
        assert "total_detected" in stats
        assert "detector_stats" in stats
        assert stats["total_processed"] >= 2


class TestDetectionScoring:
    """Test cases for detection scoring accuracy."""
    
    def test_score_ranges(self):
        """Test that scores are within expected ranges."""
        detectors = [XSSDetector(), SQLiDetector(), SSRFDetector(), DatabaseIssuesDetector()]
        
        for detector in detectors:
            # Test with empty log
            empty_log = {"message": ""}
            detected, score, evidence = detector.detect(empty_log)
            assert 0.0 <= score <= 1.0
            
            # Test with benign content
            benign_log = {"message": "Normal operation completed successfully"}
            detected, score, evidence = detector.detect(benign_log)
            assert 0.0 <= score <= 1.0
    
    def test_high_confidence_detections(self):
        """Test that obvious attacks get high confidence scores."""
        high_confidence_cases = [
            (XSSDetector(), {"message": "<script>document.cookie=''</script> onerror=alert(1)"}),
            (SQLiDetector(), {"message": "'; DROP TABLE users; --"}),
            (SSRFDetector(), {"message": "GET http://169.254.169.254/latest/meta-data/"}),
            (DatabaseIssuesDetector(), {"message": "DB_TIMEOUT: deadlock detected"})
        ]
        
        for detector, log_entry in high_confidence_cases:
            detected, score, evidence = detector.detect(log_entry)
            assert detected is True
            assert score >= 0.7, f"{detector.name} should have high confidence for obvious attack"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])