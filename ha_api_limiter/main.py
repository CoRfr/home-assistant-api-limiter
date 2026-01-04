"""Main FastAPI application for HA API Limiter."""

import argparse
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response

from .config import Mode, Settings, WhitelistConfig, settings
from .learner import Learner
from .limiter import Limiter
from .proxy import HAProxy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global instances
proxy: HAProxy | None = None
whitelist: WhitelistConfig | None = None
learner: Learner | None = None
limiter: Limiter | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler for startup and shutdown."""
    global proxy, whitelist, learner, limiter

    # Initialize proxy
    proxy = HAProxy(settings.ha_url)
    await proxy.startup()
    logger.info(f"Proxy initialized, forwarding to: {settings.ha_url}")

    # Initialize whitelist config
    whitelist = WhitelistConfig(settings.config_path)

    if settings.mode == Mode.LEARN:
        logger.info("Starting in LEARN mode - tracking accessed endpoints/entities")
        learner = Learner(whitelist)
        # Load existing whitelist if present (to append to it)
        if settings.config_path.exists():
            whitelist.load()
            logger.info(f"Loaded existing whitelist from {settings.config_path}")
    else:
        logger.info("Starting in LIMIT mode - enforcing whitelist restrictions")
        whitelist.load()
        limiter = Limiter(whitelist)
        logger.info(
            f"Loaded whitelist: {len(whitelist.endpoints)} endpoints, "
            f"{len(whitelist.entities)} entities"
        )

    yield

    # Shutdown
    if learner:
        logger.info("Saving learned whitelist on shutdown...")
        learner.save()

    await proxy.shutdown()
    logger.info("Proxy shutdown complete")


app = FastAPI(
    title="HA API Limiter",
    description="MITM proxy for Home Assistant that limits accessible endpoints and sensors",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "mode": settings.mode.value,
        "ha_url": settings.ha_url,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(request: Request, path: str) -> Response:
    """Catch-all route that proxies requests to Home Assistant."""
    full_path = f"/{path}"

    # In limit mode, check whitelist first
    if limiter:
        result = limiter.check_request(full_path, request.method)
        if not result.allowed:
            return Response(
                content=f'{{"error": "{result.reason}"}}',
                status_code=403,
                media_type="application/json",
            )

    # Forward request to Home Assistant
    if proxy is None:
        return Response(
            content='{"error": "Proxy not initialized"}',
            status_code=503,
            media_type="application/json",
        )
    response, upstream_response = await proxy.forward_request(request)

    # In learn mode, track the request and response
    if learner:
        learner.learn_from_request(full_path, request.url.query)
        learner.learn_from_response(upstream_response)
        learner.maybe_save()

    return response


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Home Assistant API Limiter - MITM proxy for limiting API access"
    )
    parser.add_argument(
        "--ha-url",
        type=str,
        help=f"Home Assistant URL (default: {Settings.model_fields['ha_url'].default})",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["learn", "limit"],
        help=f"Operating mode (default: {Settings.model_fields['mode'].default.value})",
    )
    parser.add_argument(
        "--config",
        type=str,
        dest="config_path",
        help=f"Path to whitelist config (default: {Settings.model_fields['config_path'].default})",
    )
    parser.add_argument(
        "--port",
        type=int,
        help=f"Listen port (default: {Settings.model_fields['port'].default})",
    )
    parser.add_argument(
        "--host",
        type=str,
        help=f"Listen host (default: {Settings.model_fields['host'].default})",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    global settings

    args = parse_args()

    # Override settings from CLI args
    overrides = {}
    if args.ha_url:
        overrides["ha_url"] = args.ha_url
    if args.mode:
        overrides["mode"] = Mode(args.mode)
    if args.config_path:
        overrides["config_path"] = args.config_path
    if args.port:
        overrides["port"] = args.port
    if args.host:
        overrides["host"] = args.host

    if overrides:
        # Create new settings with overrides
        from .config import settings as _settings

        for key, value in overrides.items():
            setattr(_settings, key, value)

    # Import settings again to get updated values
    from .config import settings

    logger.info(f"Starting HA API Limiter on {settings.host}:{settings.port}")
    logger.info(f"Mode: {settings.mode.value}")
    logger.info(f"Home Assistant URL: {settings.ha_url}")
    logger.info(f"Config path: {settings.config_path}")

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
