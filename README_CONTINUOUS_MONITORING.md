# ReliabilityAgent Member A - Continuous Security Monitoring

## Overview

The ReliabilityAgent Member A is a continuous security monitoring system that:

1. **Polls log streams** from dummy backend every 2 seconds
2. **Detects security issues** using ML-based pattern matching
3. **Forwards detections** to Member B service with confidence scores
4. **Operates continuously** without manual intervention

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Dummy Backend  │    │   Member A      │    │   Member B      │
│  (Log Generator)│    │  (Detection)    │    │  (Processing)   │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Generates logs│───▶│ • Polls logs    │───▶│ • Receives      │
│ • XSS payloads  │    │ • Detects XSS   │    │   detections    │
│ • SQLi attempts │    │ • Detects SQLi  │    │ • Classification│
│ • SSRF requests │    │ • Detects SSRF  │    │ • Storage       │
│ • DB timeouts   │    │ • Detects DB    │    │ • Alerting      │
│ • REST API      │    │ • Forwards events│    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Start the Dummy Backend (Log Generator)
```bash
cd dummy_backend
python dummy_backend.py
```
**Runs on:** http://localhost:9000
**Generates:** Realistic logs with malicious payloads every 15 logs

### 2. Start Member A (Detection Service)  
```bash
cd backend/ingestion/app
python main.py
```
**Runs on:** http://localhost:8000
**Polls:** Dummy backend every 2 seconds automatically

### 3. Verify Operation
```bash
# Check Member A health and metrics
curl http://localhost:8000/healthz
curl http://localhost:8000/metrics

# Check dummy backend log generation
curl http://localhost:9000/logs/recent?limit=10
curl http://localhost:9000/logs/stats
```

## Security Detection Capabilities

### XSS (Cross-Site Scripting)
- **Patterns:** `<script>`, `onerror=`, `onload=`, `javascript:`, `eval()`, obfuscated tags
- **Scoring:** Basic match: 0.45, Event handlers: 0.6, Obfuscated: 0.65+
- **Example:** `<script>alert('XSS')</script>` → Score: 0.45

### SQLi (SQL Injection)
- **Patterns:** `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `--`, `/**/`, `INFORMATION_SCHEMA`
- **Scoring:** Basic: 0.2, OR bypass: 0.6, DROP TABLE: 0.8
- **Example:** `admin' OR 1=1 --` → Score: 0.6

### SSRF (Server-Side Request Forgery)
- **Patterns:** `169.254.169.254`, AWS metadata, `localhost`, internal IPs, `file://`
- **Scoring:** AWS metadata: 0.9, Internal access: 0.5-0.8
- **Example:** `http://169.254.169.254/latest/meta-data/` → Score: 0.9

### Database Issues
- **Patterns:** Timeouts, deadlocks, connection failures, latency extraction
- **Scoring:** Timeout: 0.7, Deadlock: 0.8, High latency: 0.4-0.8
- **Example:** `connection timed out after 3500ms` → Score: 0.6

## API Endpoints

### Member A (Detection Service) - Port 8000

#### Health & Monitoring
- `GET /healthz` - Health check with Member B connectivity
- `GET /metrics` - Detection statistics and service metrics
- `GET /` - Service information and status

#### Admin Control
- `POST /simulate/start` - Start continuous log polling
- `POST /simulate/stop` - Stop continuous log polling

#### Legacy (Still Supported)
- `POST /webhook/event` - Manual event submission
- `POST /simulate/{scenario}` - Generate test events

### Dummy Backend (Log Generator) - Port 9000

#### Log Streaming
- `GET /logs/recent?limit=50` - Get recent logs
- `GET /logs/stream?since=timestamp` - Get logs since timestamp
- `GET /logs/stats` - Generation statistics

#### Control
- `POST /logs/start` - Start log generation
- `POST /logs/stop` - Stop log generation
- `GET /health` - Generator health check

## Configuration

### Environment Variables

```bash
# Member B forwarding
MEMBER_B_URL=https://your-ngrok-url.ngrok-free.app/events
MAX_FORWARD_RETRIES=3
FORWARD_RETRY_BACKOFF=1.0

# Continuous monitoring
DUMMY_BACKEND_URL=http://localhost:9000
POLL_INTERVAL_SECONDS=2.0
ENABLE_CONTINUOUS_POLLING=true

# Detection settings
MIN_DETECTION_SCORE=0.3
MAX_PAYLOAD_LENGTH=2000

# Service settings
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO
SERVICE_NAME=ingestion
```

### Config File (.env)
Create `.env` file in project root:
```env
MEMBER_B_URL=https://your-member-b-url.com/events
POLL_INTERVAL_SECONDS=2.0
MIN_DETECTION_SCORE=0.3
LOG_LEVEL=INFO
```

## Testing

### Unit Tests
```bash
# Test detection logic
cd backend/ingestion/app
python -m pytest test_detectors.py -v

# Specific detector tests
python -m pytest test_detectors.py::TestXSSDetector -v
python -m pytest test_detectors.py::TestSQLiDetector -v
```

### Integration Tests
```bash
# Test complete pipeline
python -m pytest test_integration.py -v

# Test with mocked Member B
python -m pytest test_integration.py::TestMemberBForwarding -v
```

### Manual Testing
```bash
# 1. Generate malicious log in dummy backend
curl -X POST "http://localhost:9000/logs/start"

# 2. Watch Member A detect and forward
curl "http://localhost:8000/metrics"

# 3. Check Member B receives events (check your ngrok URL logs)
```

## Payload Format

### Raw Events Sent to Member B
```json
{
  "source": "dummy-service",
  "type": "log", 
  "payload": "User input: <script>alert('XSS')</script>\n\nStack Trace: ...",
  "metadata": {
    "service": "dummy-service",
    "host": "dummy-host",
    "level": "WARN",
    "detector": "XSS",
    "score": 0.65,
    "evidence": {
      "matched_patterns": ["script_tag"],
      "content_snippet": "User input: <script>alert('XSS')</script>",
      "detector": "XSS"
    },
    "original_timestamp": "2025-09-21T12:34:56.789Z",
    "detection_timestamp": "2025-09-21T12:34:57.123Z"
  },
  "event_timestamp": "2025-09-21T12:34:56.789Z"
}
```

## Monitoring & Observability

### Metrics Available
```json
{
  "service_metrics": {
    "logs_processed": 1250,
    "detections_found": 45,
    "events_forwarded": 42,
    "forwarding_failures": 3,
    "polling_active": true,
    "last_poll_time": "2025-09-21T12:34:56Z"
  },
  "detection_stats": {
    "total_processed": 1250,
    "total_detected": 45,
    "detector_stats": {
      "XSS": {"detection_count": 15},
      "SQLi": {"detection_count": 12},
      "SSRF": {"detection_count": 8},
      "DB_TIMEOUT": {"detection_count": 10}
    }
  }
}
```

### Log Levels
- **INFO:** Service lifecycle, successful detections
- **WARN:** Failed polling attempts, low-score detections
- **ERROR:** Forwarding failures, detection errors
- **DEBUG:** Detailed polling info, all log processing

## Troubleshooting

### Common Issues

#### 1. No Detections Found
```bash
# Check if dummy backend is generating malicious logs
curl http://localhost:9000/logs/stats

# Verify detection score threshold
curl http://localhost:8000/metrics | jq '.configuration.min_detection_score'

# Check logs for processing
tail -f logs/ingestion.log | grep "🚨"
```

#### 2. Member B Not Receiving Events
```bash
# Test Member B connectivity
curl http://localhost:8000/healthz | jq '.member_b_reachable'

# Check forwarding failures
curl http://localhost:8000/metrics | jq '.service_metrics.forwarding_failures'

# Verify Member B URL in config
curl http://localhost:8000/ | jq '.member_b_url'
```

#### 3. Polling Not Working
```bash
# Check if polling is active
curl http://localhost:8000/metrics | jq '.service_metrics.polling_active'

# Restart polling
curl -X POST http://localhost:8000/simulate/start

# Check dummy backend health
curl http://localhost:9000/health
```

### Performance Tuning

#### Adjust Polling Frequency
```bash
# Faster polling (1 second)
export POLL_INTERVAL_SECONDS=1.0

# Slower polling (5 seconds) 
export POLL_INTERVAL_SECONDS=5.0
```

#### Adjust Detection Sensitivity
```bash
# More sensitive (catch more, possible false positives)
export MIN_DETECTION_SCORE=0.1

# Less sensitive (fewer false positives)
export MIN_DETECTION_SCORE=0.5
```

## Production Deployment

### Docker Compose Example
```yaml
version: '3.8'
services:
  dummy-backend:
    build: ./dummy_backend
    ports:
      - "9000:9000"
    environment:
      - NORMAL_LOG_INTERVAL=2.0
      - MALICIOUS_LOG_EVERY_N=15

  member-a:
    build: ./backend/ingestion
    ports:
      - "8000:8000"
    environment:
      - MEMBER_B_URL=https://your-member-b.com/events
      - DUMMY_BACKEND_URL=http://dummy-backend:9000
      - POLL_INTERVAL_SECONDS=2.0
      - MIN_DETECTION_score=0.3
    depends_on:
      - dummy-backend
```

### Security Considerations
- **Input Validation:** All log content treated as untrusted
- **Payload Limits:** Messages truncated to prevent memory issues  
- **Rate Limiting:** Consider adding rate limits for high-volume environments
- **TLS:** Use HTTPS for Member B communication in production
- **Monitoring:** Set up alerts on forwarding failures and detection anomalies

## Development

### Adding New Detectors
1. Create new detector class in `detectors.py`
2. Inherit from `SecurityDetector` base class
3. Implement `detect()` method returning `(bool, float, dict)`
4. Add to `DetectionEngine.detectors` list
5. Write unit tests in `test_detectors.py`

### Example New Detector
```python
class CommandInjectionDetector(SecurityDetector):
    def __init__(self):
        super().__init__("CMD_INJECTION")
        self.patterns = {
            "shell_meta": re.compile(r"[;&|`$(){}]", re.IGNORECASE),
            "command_substitution": re.compile(r"`[^`]+`|\$\([^)]+\)", re.IGNORECASE)
        }
    
    def detect(self, log_entry):
        content = self._extract_text_content(log_entry)
        # Implementation here...
        return detected, score, evidence
```

## License

MIT License - See LICENSE file for details.

## Support

For issues and questions:
- Check the troubleshooting section above
- Review logs in `logs/` directory  
- Test individual components with curl commands
- Verify configuration with `/metrics` endpoint