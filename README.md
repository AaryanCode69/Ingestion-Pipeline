# ReliabilityAgent Ingestion Service (Member A)

FastAPI-based ingestion service for the ReliabilityAgent hackathon project. This service handles webhook events, validates them, and forwards them to Member B (Processor Service) for processing and storage.

## Features

- 🔌 **Webhook Endpoint**: Receives events from external systems
- � **HTTP Forwarding**: Forwards validated events to Member B service
- 🔄 **Retry Logic**: Exponential backoff retry for network failures
- 🎭 **Event Simulation**: Generates fake security/operational events for testing
- 📊 **Health Monitoring**: Health checks and Member B connectivity status
- 🐳 **Docker Ready**: Lightweight containerized deployment

## Architecture Overview

This service is **Member A** in the 4-part ReliabilityAgent system:

1. **Ingestion Service** (this) → Validates events, forwards to Member B
2. **Processor Service** (Member B) → Processes, classifies, stores events
3. **Agent Service** (Member C) → Retrieves incidents, generates responses  
4. **Dashboard** (Member D) → Visualizes incidents and actions

## Quick Start

### Prerequisites

- Python 3.10+
- Member B service running and accessible

### Installation

1. **Clone and navigate to the service:**
   ```bash
   cd backend/ingestion
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your Member B service URL
   ```

4. **Start the service:**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## API Endpoints

### Core Endpoints

- `POST /webhook/event` - Receive and forward events to Member B
- `POST /simulate/{scenario}` - Generate fake events for testing
- `GET /health` - Health check and Member B connectivity
- `GET /status` - Detailed service status and configuration
- `GET /scenarios` - Available simulation scenarios

### Event Schema

Events must match the exact `raw_events` schema:

```json
{
  "source": "comments-service",
  "type": "http_request",
  "payload": "POST /api/comments HTTP/1.1\n...",
  "metadata": {
    "env": "staging",
    "service": "comments",
    "deploy": "v1.2.3"
  },
  "event_timestamp": "2025-09-21T12:34:56.789Z"
}
```

### Available Simulation Scenarios

- `xss` - Cross-site scripting attacks in HTTP requests
- `db_timeout` - Database connection timeout errors

### Example Usage

**Receive a webhook event:**
```bash
curl -X POST "http://localhost:8000/webhook/event" \
     -H "Content-Type: application/json" \
     -d '{
       "source": "comments-service",
       "type": "http_request", 
       "payload": "POST /api/comments HTTP/1.1\nContent-Type: application/json\n\n{\"comment\":\"<script>alert(1)</script>\"}",
       "metadata": {"env": "production", "service": "comments"},
       "event_timestamp": "2025-09-21T12:34:56.789Z"
     }'
```

**Simulate XSS attacks:**
```bash
curl -X POST "http://localhost:8000/simulate/xss" \
     -H "Content-Type: application/json" \
     -d '{"count": 3, "delay_seconds": 1.0}'
```

**Check service health:**
```bash
curl http://localhost:8000/health
```

## Configuration

Key environment variables:

- `MEMBER_B_URL` - URL of Member B service (e.g., `http://localhost:9000/raw_events`)
- `MAX_FORWARD_RETRIES` - Maximum retry attempts for forwarding (default: 3)
- `FORWARD_RETRY_BACKOFF` - Base retry delay in seconds (default: 1.0)
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

## Forwarding Behavior

When an event is received:

1. **Validation**: Pydantic validates the incoming JSON
2. **Forwarding**: HTTP POST to Member B with exponential backoff retry
3. **Response**: Returns Member B's response status and body

### Retry Logic

- **Base delay**: `FORWARD_RETRY_BACKOFF` seconds
- **Exponential backoff**: delay × (2 ^ attempt_number)
- **Max attempts**: `MAX_FORWARD_RETRIES + 1`
- **Timeout**: 30 seconds per request

### Error Handling

- **400 Bad Request**: Invalid event schema
- **502 Bad Gateway**: Member B unreachable after retries
- **200 OK**: Event forwarded successfully (even if Member B returned non-2xx)

## Docker Deployment

**Build image:**
```bash
docker build -t reliability-agent-ingestion .
```

**Run container:**
```bash
docker run -p 8000:8000 \
  -e MEMBER_B_URL="http://member-b:9000/raw_events" \
  -e MAX_FORWARD_RETRIES=3 \
  reliability-agent-ingestion
```

## Development

**Install development dependencies:**
```bash
pip install -r requirements.txt
```

**Run tests:**
```bash
pytest
```

**Format code:**
```bash
black app/
isort app/
```

## Monitoring

- **Health check**: `GET /health` - Member B connectivity status
- **Service status**: `GET /status` - Detailed configuration and status
- **Available scenarios**: `GET /scenarios` - List simulation options

## Integration with Member B

The service forwards events to Member B using the exact `raw_events` schema. Member B should expect:

- HTTP POST requests to the configured endpoint
- JSON payload matching the event schema
- Proper error handling for processing failures

## Security Considerations

- Input validation with Pydantic models
- Configurable CORS for production environments  
- Non-root Docker user
- Environment-based configuration
- Request timeout protection