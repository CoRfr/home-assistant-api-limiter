"""HTTP proxy module for forwarding requests to Home Assistant."""

import asyncio
import logging
from urllib.parse import urlparse

import httpx
import websockets
from fastapi import Request, Response, WebSocket, WebSocketDisconnect

from .config import settings

logger = logging.getLogger(__name__)

# Headers that should not be forwarded
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    # Content headers - let FastAPI recompute these since httpx decompresses content
    "content-length",
    "content-encoding",
}


class HAProxy:
    """Async HTTP proxy for Home Assistant API requests."""

    def __init__(self, ha_url: str | None = None):
        self.ha_url = (ha_url or settings.ha_url).rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def startup(self) -> None:
        """Initialize the HTTP client."""
        self._client = httpx.AsyncClient(
            base_url=self.ha_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
        )

    async def shutdown(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the HTTP client, raising if not initialized."""
        if not self._client:
            raise RuntimeError("Proxy not initialized. Call startup() first.")
        return self._client

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Filter out hop-by-hop headers."""
        return {
            key: value for key, value in headers.items() if key.lower() not in HOP_BY_HOP_HEADERS
        }

    async def forward_request(self, request: Request) -> tuple[Response, httpx.Response]:
        """
        Forward a request to Home Assistant and return the response.

        Returns:
            Tuple of (FastAPI Response, raw httpx Response for inspection)
        """
        # Build the target URL
        target_path = request.url.path
        if request.url.query:
            target_path = f"{target_path}?{request.url.query}"

        # Get request body
        body = await request.body()

        # Filter headers for forwarding
        headers = self._filter_headers(dict(request.headers))

        # Make the proxied request
        upstream_response = await self.client.request(
            method=request.method,
            url=target_path,
            headers=headers,
            content=body,
        )

        # Build response headers (filter hop-by-hop)
        response_headers = self._filter_headers(dict(upstream_response.headers))

        # Create FastAPI response
        response = Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

        return response, upstream_response

    def _get_ws_url(self, path: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        parsed = urlparse(self.ha_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{ws_scheme}://{parsed.netloc}{path}"

    async def forward_websocket(self, websocket: WebSocket, path: str) -> None:
        """
        Forward a WebSocket connection to Home Assistant.

        Args:
            websocket: The incoming FastAPI WebSocket connection
            path: The WebSocket path (e.g., /api/websocket)
        """
        await websocket.accept()

        ws_url = self._get_ws_url(path)
        logger.info(f"Connecting to upstream WebSocket: {ws_url}")

        try:
            async with websockets.connect(ws_url) as upstream_ws:
                logger.info(f"WebSocket connected to {ws_url}")

                async def client_to_upstream():
                    """Forward messages from client to upstream."""
                    try:
                        while True:
                            data = await websocket.receive_text()
                            await upstream_ws.send(data)
                    except WebSocketDisconnect:
                        logger.info("Client WebSocket disconnected")
                    except Exception as e:
                        logger.debug(f"Client to upstream error: {e}")

                async def upstream_to_client():
                    """Forward messages from upstream to client."""
                    try:
                        async for message in upstream_ws:
                            if isinstance(message, str):
                                await websocket.send_text(message)
                            else:
                                await websocket.send_bytes(message)
                    except Exception as e:
                        logger.debug(f"Upstream to client error: {e}")

                # Run both directions concurrently
                await asyncio.gather(
                    client_to_upstream(),
                    upstream_to_client(),
                    return_exceptions=True,
                )

        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
            try:
                await websocket.close(code=1011, reason=str(e))
            except Exception:
                pass


# Global proxy instance
proxy = HAProxy()
