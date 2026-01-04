"""HTTP proxy module for forwarding requests to Home Assistant."""

import httpx
from fastapi import Request, Response

from .config import settings

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


# Global proxy instance
proxy = HAProxy()
