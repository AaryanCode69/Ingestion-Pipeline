"""
Security Detection Module for ReliabilityAgent
Implements detection logic for XSS, SQLi, SSRF, and Database issues.
Each detector returns (detected: bool, score: float, evidence: dict).
"""
import re
import json
from typing import Tuple, Dict, Any, List
from loguru import logger


class SecurityDetector:
    """Base class for security detectors."""
    
    def __init__(self, name: str):
        self.name = name
        self.detection_count = 0
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect security issues in log entry.
        
        Returns:
            Tuple of (detected: bool, score: float, evidence: dict)
        """
        raise NotImplementedError
    
    def _extract_text_content(self, log_entry: Dict[str, Any]) -> str:
        """Extract all text content for analysis."""
        text_parts = []
        
        # Add main message
        if "message" in log_entry:
            text_parts.append(str(log_entry["message"]))
        
        # Add stack trace if present
        if "stack_trace" in log_entry:
            text_parts.append(str(log_entry["stack_trace"]))
        
        # Add any payload data
        if "payload" in log_entry:
            text_parts.append(str(log_entry["payload"]))
        
        return " ".join(text_parts)


class XSSDetector(SecurityDetector):
    """Cross-Site Scripting (XSS) detector."""
    
    def __init__(self):
        super().__init__("XSS")
        
        # Regex patterns for XSS detection (case-insensitive)
        self.patterns = {
            "script_tag": re.compile(r"<\s*script\b", re.IGNORECASE),
            "script_events": re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.IGNORECASE),
            "iframe_javascript": re.compile(r"<\s*iframe\s+[^>]*src\s*=\s*[\"']?\s*javascript:", re.IGNORECASE),
            "document_cookie": re.compile(r"document\s*\.\s*cookie", re.IGNORECASE),
            "eval_function": re.compile(r"eval\s*\(", re.IGNORECASE),
            "inner_html": re.compile(r"innerHTML\s*=", re.IGNORECASE),
            "obfuscated_script": re.compile(r"<\s*s\s*c\s*r\s*i\s*p\s*t", re.IGNORECASE),
            "data_uri": re.compile(r"data:\s*text/html", re.IGNORECASE),
            "vbscript": re.compile(r"vbscript:", re.IGNORECASE),
            "expression": re.compile(r"expression\s*\(", re.IGNORECASE)
        }
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Detect XSS patterns in log entry."""
        content = self._extract_text_content(log_entry)
        
        matches = []
        score = 0.0
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                matches.append(pattern_name)
                
                # Scoring logic
                if pattern_name in ["script_tag", "iframe_javascript"]:
                    score += 0.45
                elif pattern_name in ["script_events", "document_cookie"]:
                    score += 0.6
                elif pattern_name == "obfuscated_script":
                    score += 0.65
                elif pattern_name in ["eval_function", "expression"]:
                    score += 0.4
                else:
                    score += 0.3
        
        # Cap score at 1.0
        score = min(score, 1.0)
        detected = len(matches) > 0
        
        if detected:
            self.detection_count += 1
            logger.debug(f"XSS detected: {matches}, score: {score:.3f}")
        
        evidence = {
            "matched_patterns": matches,
            "pattern_count": len(matches),
            "content_snippet": content[:200] + "..." if len(content) > 200 else content,
            "detector": "XSS"
        }
        
        return detected, score, evidence


class SQLiDetector(SecurityDetector):
    """SQL Injection detector."""
    
    def __init__(self):
        super().__init__("SQLi")
        
        # SQL injection patterns
        self.patterns = {
            "union_select": re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
            "or_equals": re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE),
            "drop_table": re.compile(r"['\"]?\s*;\s*DROP\s+TABLE", re.IGNORECASE),
            "comment_bypass": re.compile(r"--\s", re.IGNORECASE),
            "multiline_comment": re.compile(r"/\*.*?\*/", re.DOTALL | re.IGNORECASE),
            "admin_bypass": re.compile(r"(admin|root)['\"]?\s*(OR|AND)\s*['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
            "sleep_function": re.compile(r"\b(SLEEP|WAITFOR|DELAY)\s*\(", re.IGNORECASE),
            "information_schema": re.compile(r"\bINFORMATION_SCHEMA\b", re.IGNORECASE),
            "concat_function": re.compile(r"\bCONCAT\s*\(", re.IGNORECASE),
            "version_function": re.compile(r"\b(VERSION|@@VERSION)\b", re.IGNORECASE)
        }
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Detect SQL injection patterns."""
        content = self._extract_text_content(log_entry)
        
        matches = []
        score = 0.0
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                matches.append(pattern_name)
                
                # Scoring logic
                if pattern_name in ["drop_table"]:
                    score += 0.8
                elif pattern_name in ["union_select", "or_equals", "admin_bypass"]:
                    score += 0.6
                elif pattern_name in ["sleep_function", "information_schema"]:
                    score += 0.5
                elif pattern_name in ["comment_bypass", "multiline_comment"]:
                    score += 0.3
                else:
                    score += 0.2
        
        score = min(score, 1.0)
        detected = len(matches) > 0
        
        if detected:
            self.detection_count += 1
            logger.debug(f"SQLi detected: {matches}, score: {score:.3f}")
        
        evidence = {
            "matched_patterns": matches,
            "pattern_count": len(matches),
            "content_snippet": content[:200] + "..." if len(content) > 200 else content,
            "detector": "SQLi"
        }
        
        return detected, score, evidence


class SSRFDetector(SecurityDetector):
    """Server-Side Request Forgery (SSRF) detector."""
    
    def __init__(self):
        super().__init__("SSRF")
        
        # SSRF patterns
        self.patterns = {
            "aws_metadata": re.compile(r"169\.254\.169\.254", re.IGNORECASE),
            "aws_metadata_path": re.compile(r"http://169\.254\.169\.254/latest/", re.IGNORECASE),
            "localhost": re.compile(r"\b(localhost|127\.0\.0\.1)\b", re.IGNORECASE),
            "internal_ip": re.compile(r"\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)", re.IGNORECASE),
            "file_protocol": re.compile(r"file://", re.IGNORECASE),
            "gopher_protocol": re.compile(r"gopher://", re.IGNORECASE),
            "metadata_endpoints": re.compile(r"/latest/meta-data|/computeMetadata/v1/", re.IGNORECASE),
            "curl_internal": re.compile(r"curl\s+.*?(127\.0\.0\.1|localhost|169\.254\.)", re.IGNORECASE)
        }
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Detect SSRF patterns."""
        content = self._extract_text_content(log_entry)
        
        matches = []
        score = 0.0
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                matches.append(pattern_name)
                
                # Scoring logic
                if pattern_name in ["aws_metadata", "aws_metadata_path"]:
                    score += 0.9
                elif pattern_name in ["metadata_endpoints", "curl_internal"]:
                    score += 0.8
                elif pattern_name in ["file_protocol", "gopher_protocol"]:
                    score += 0.7
                elif pattern_name == "localhost":
                    score += 0.5
                elif pattern_name == "internal_ip":
                    score += 0.4
        
        score = min(score, 1.0)
        detected = len(matches) > 0
        
        if detected:
            self.detection_count += 1
            logger.debug(f"SSRF detected: {matches}, score: {score:.3f}")
        
        evidence = {
            "matched_patterns": matches,
            "pattern_count": len(matches),
            "content_snippet": content[:200] + "..." if len(content) > 200 else content,
            "detector": "SSRF"
        }
        
        return detected, score, evidence


class DatabaseIssuesDetector(SecurityDetector):
    """Database performance and connectivity issues detector."""
    
    def __init__(self):
        super().__init__("DB_TIMEOUT")
        
        # Database issue patterns
        self.patterns = {
            "timeout": re.compile(r"\btimeout\b", re.IGNORECASE),
            "connection_timeout": re.compile(r"connection\s+timed?\s+out", re.IGNORECASE),
            "deadlock": re.compile(r"deadlock\s+detected", re.IGNORECASE),
            "cannot_connect": re.compile(r"(could not connect|connection refused|connection failed)", re.IGNORECASE),
            "db_timeout_explicit": re.compile(r"DB_TIMEOUT", re.IGNORECASE),
            "query_timeout": re.compile(r"query\s+timeout", re.IGNORECASE),
            "connection_pool": re.compile(r"connection\s+pool\s+(exhausted|full)", re.IGNORECASE),
            "too_many_connections": re.compile(r"too\s+many\s+connections", re.IGNORECASE)
        }
        
        # Latency extraction pattern
        self.latency_pattern = re.compile(r"latency[=:\s]*(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|seconds?)", re.IGNORECASE)
    
    def detect(self, log_entry: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Detect database issues."""
        content = self._extract_text_content(log_entry)
        
        matches = []
        score = 0.0
        extracted_latency = None
        
        # Check for patterns
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(content):
                matches.append(pattern_name)
                
                # Scoring logic
                if pattern_name in ["deadlock", "db_timeout_explicit"]:
                    score += 0.8
                elif pattern_name in ["connection_timeout", "cannot_connect"]:
                    score += 0.7
                elif pattern_name in ["query_timeout", "connection_pool", "too_many_connections"]:
                    score += 0.6
                elif pattern_name == "timeout":
                    score += 0.4
        
        # Extract latency if present
        latency_match = self.latency_pattern.search(content)
        if latency_match:
            try:
                latency_value = float(latency_match.group(1))
                unit = latency_match.group(2).lower()
                
                # Convert to milliseconds
                if unit.startswith('s'):
                    latency_ms = latency_value * 1000
                else:
                    latency_ms = latency_value
                
                extracted_latency = latency_ms
                
                # Score based on latency thresholds
                if latency_ms > 5000:  # > 5 seconds
                    score += 0.8
                elif latency_ms > 2000:  # > 2 seconds  
                    score += 0.6
                elif latency_ms > 1000:  # > 1 second
                    score += 0.4
                
            except (ValueError, AttributeError):
                pass
        
        score = min(score, 1.0)
        detected = len(matches) > 0 or extracted_latency is not None
        
        if detected:
            self.detection_count += 1
            logger.debug(f"DB Issues detected: {matches}, latency: {extracted_latency}, score: {score:.3f}")
        
        evidence = {
            "matched_patterns": matches,
            "pattern_count": len(matches),
            "extracted_latency_ms": extracted_latency,
            "content_snippet": content[:200] + "..." if len(content) > 200 else content,
            "stack_trace_snippet": log_entry.get("stack_trace", "")[:500] if log_entry.get("stack_trace") else None,
            "detector": "DB_TIMEOUT"
        }
        
        return detected, score, evidence


class DetectionEngine:
    """Main detection engine that runs all detectors."""
    
    def __init__(self):
        self.detectors = [
            XSSDetector(),
            SQLiDetector(), 
            SSRFDetector(),
            DatabaseIssuesDetector()
        ]
        self.total_processed = 0
        self.total_detected = 0
    
    def process_log_entry(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process a log entry through all detectors.
        
        Returns:
            List of detection results for any positive detections.
        """
        self.total_processed += 1
        detections = []
        
        for detector in self.detectors:
            try:
                detected, score, evidence = detector.detect(log_entry)
                
                if detected:
                    self.total_detected += 1
                    
                    detection_result = {
                        "detector": detector.name,
                        "detected": detected,
                        "score": score,
                        "evidence": evidence,
                        "log_entry": log_entry
                    }
                    
                    detections.append(detection_result)
                    
                    logger.info(f"🚨 {detector.name} detection - Score: {score:.3f} - {evidence.get('matched_patterns', [])}")
            
            except Exception as e:
                logger.error(f"Error in {detector.name} detector: {e}")
        
        return detections
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        return {
            "total_processed": self.total_processed,
            "total_detected": self.total_detected,
            "detector_stats": {
                detector.name: {
                    "detection_count": detector.detection_count
                }
                for detector in self.detectors
            }
        }


# Global detection engine instance
detection_engine = DetectionEngine()


def process_log_entry(log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Process a single log entry through all security detectors.
    
    Args:
        log_entry: Dictionary containing log data with keys like:
                  timestamp, level, message, service, host, stack_trace
    
    Returns:
        List of detection results for any positive detections.
    """
    return detection_engine.process_log_entry(log_entry)


def get_detection_stats() -> Dict[str, Any]:
    """Get current detection statistics."""
    return detection_engine.get_stats()