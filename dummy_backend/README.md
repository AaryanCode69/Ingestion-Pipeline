# ReliabilityAgent Dummy Backend (Member B)

Simple FastAPI service that acts as Member B for testing the integration with Member A (Ingestion Service). This dummy backend receives events forwarded from Member A and logs the details for verification.

## Purpose

This is a **testing-only** service that:
- Receives events from Member A via `POST /raw_events`
- Validates incoming JSON against the `raw_events` schema
- Logs event details including source, type, timestamp, and metadata
- Returns confirmation responses
- **Does NOT** perform real classification, storage, or processing

## Quick Start

### Prerequisites
- Python 3.10+

### Installation

1. **Navigate to dummy backend directory:**
   ```bash
   cd dummy_backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the service:**
   ```bash
   python dummy_backend.py
   ```

   Or with uvicorn:
   ```bash
   uvicorn dummy_backend:app --host 0.0.0.0 --port 9000 --reload
   ```

4. **Verify it's running:**
   ```bash
   curl http://localhost:9000/health
   ```

## API Endpoints

### Core Endpoints
- `POST /raw_events` - Receive events from Member A
- `GET /health` - Health check
- `GET /` - Service information
- `GET /stats` - Basic stats (dummy data)
- `GET /docs` - Swagger documentation

### Event Schema

The service expects events matching the exact `raw_events` schema:

```json
{
  "source": "comments-service",
  "type": "http_request",
  "payload": "POST /api/comments HTTP/1.1\nContent-Type: application/json\n\n{\"comment\":\"<script>alert('XSS')</script>\"}",
  "metadata": {
    "env": "staging",
    "service": "comments",
    "deploy": "v1.2.3"
  },
  "event_timestamp": "2025-09-21T12:34:56.789Z"
}
```

### Response Format

On successful receipt:

```json
{
  "status": "received",
  "source": "comments-service",
  "event_timestamp": "2025-09-21T12:34:56.789Z",
  "metadata": {
    "env": "staging",
    "service": "comments",
    "deploy": "v1.2.3"
  }
}
```

## Testing Integration

### Test Event Forwarding

1. **Start dummy backend:**
   ```bash
   cd dummy_backend
   python dummy_backend.py
   ```

2. **Start Member A ingestion service:**
   ```bash
   cd backend/ingestion
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

3. **Send test event to Member A:**
   ```bash
   curl -X POST "http://localhost:8000/webhook/event" \
        -H "Content-Type: application/json" \
        -d '{
          "source": "test-service",
          "type": "http_request",
          "payload": "Test payload from Member A",
          "metadata": {"env": "test", "service": "integration"},
          "event_timestamp": "2025-09-21T12:34:56.789Z"
        }'
   ```

4. **Check dummy backend logs** - You should see detailed logging of the received event.

### Test Simulation

```bash
# Test XSS simulation forwarding
curl -X POST "http://localhost:8000/simulate/xss" \
     -H "Content-Type: application/json" \
     -d '{"count": 2, "delay_seconds": 1.0}'
```

## Logging Output

The dummy backend logs detailed information about received events:

```
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:123 | 📥 Received event from Member A:
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:124 |    Source: comments-service
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:125 |    Type: http_request
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:126 |    Timestamp: 2025-09-21 12:34:56.789000+00:00
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:130 |    Metadata:
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:132 |      env: staging
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:132 |      service: comments
2025-09-21 12:34:56 | INFO | dummy_backend:receive_raw_event:132 |      deploy: v1.2.3
```

## Configuration

The dummy backend runs on `http://localhost:9000` by default, which matches the `member_b_url` setting in Member A's configuration.

To change the port, modify the `uvicorn.run()` call in `dummy_backend.py` or set environment variables.

## Error Handling

- **422 Unprocessable Entity**: Invalid JSON schema
- **500 Internal Server Error**: Processing errors
- **200 OK**: Successful event receipt

## Next Steps

Once integration testing is complete with this dummy backend, you can replace it with the real Member B service that will:
- Store events in the database
- Perform classification (XSS detection, anomaly detection)
- Generate embeddings
- Create incidents and memory items

This dummy backend provides the foundation for that integration!