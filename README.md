# Home Assistant API Limiter

A MITM proxy for Home Assistant that limits accessible API endpoints and entity sensors.

## Overview

This service acts as a reverse proxy between clients and Home Assistant, providing two operating modes:

- **Learn mode**: Monitors all API requests and builds a whitelist of accessed endpoints and entities
- **Limit mode**: Enforces the whitelist, blocking any requests to non-whitelisted endpoints or entities

## Use Cases

- Restrict IoT devices to only access specific sensors/entities
- Create isolated API access for third-party integrations
- Audit which endpoints and entities are actually being used
- Implement principle of least privilege for Home Assistant API access

## Installation

### Using Poetry

```bash
# Clone the repository
cd /path/to/home-assistant-api-limiter

# Install dependencies
poetry install

# Run in learn mode
poetry run ha-api-limiter --mode learn --ha-url http://homeassistant.local:8123

# Run in limit mode
poetry run ha-api-limiter --mode limit --ha-url http://homeassistant.local:8123
```

### Using Docker

```bash
# Build the image
docker build -t ha-api-limiter .

# Run in learn mode
docker run -d \
  --name ha-api-limiter \
  -p 8080:8080 \
  -v $(pwd)/config:/config \
  -e MODE=learn \
  -e HA_URL=http://homeassistant.local:8123 \
  ha-api-limiter

# Run in limit mode
docker run -d \
  --name ha-api-limiter \
  -p 8080:8080 \
  -v $(pwd)/config:/config \
  -e MODE=limit \
  -e HA_URL=http://homeassistant.local:8123 \
  ha-api-limiter
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HA_URL` | `http://localhost:8123` | Home Assistant URL |
| `MODE` | `limit` | Operating mode: `learn` or `limit` |
| `CONFIG_PATH` | `./config.yaml` | Path to whitelist configuration |
| `PORT` | `8080` | Proxy listen port |
| `HOST` | `0.0.0.0` | Proxy listen host |

### CLI Arguments

```bash
ha-api-limiter --help

  --ha-url URL      Home Assistant URL
  --mode MODE       Operating mode (learn/limit)
  --config PATH     Path to whitelist config
  --port PORT       Listen port
  --host HOST       Listen host
```

### Whitelist Configuration (config.yaml)

```yaml
# Whitelisted endpoint patterns
endpoints:
  - /api/states                    # List all states
  - /api/states/{entity_id}        # Get specific entity state
  - /api/services/{domain}/{service}  # Call any service
  - /api/config                    # Get HA config

# Whitelisted entity IDs (supports wildcards)
entities:
  - sensor.temperature_living_room  # Specific sensor
  - switch.bedroom_light            # Specific switch
  - light.*                         # All light entities
  - sensor.weather_*                # All weather sensors
```

## Workflow

### Learning Phase

1. Start the proxy in `learn` mode
2. Point your client/device to the proxy instead of Home Assistant directly
3. Use the client normally - all accessed endpoints and entities are recorded
4. Stop the proxy - the whitelist is saved to `config.yaml`
5. Review and edit the generated `config.yaml` if needed

### Enforcement Phase

1. Start the proxy in `limit` mode with the generated `config.yaml`
2. Point your client/device to the proxy
3. Only whitelisted endpoints and entities are accessible
4. Non-whitelisted requests receive `403 Forbidden`

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check (always allowed) |
| `/*` | All other requests are proxied to Home Assistant |

## Security Notes

- This proxy passes through Authorization headers to Home Assistant
- Ensure the proxy is only accessible from trusted networks
- The whitelist file may contain sensitive entity names - protect accordingly
- Consider using TLS termination in front of this proxy

## Development

```bash
# Install development dependencies
poetry install

# Run locally
poetry run python -m ha_api_limiter.main --mode learn

# Run with auto-reload (development)
poetry run uvicorn ha_api_limiter.main:app --reload --port 8080
```
