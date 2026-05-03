"""Endpoint discovery helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class DiscoveredEndpoint:
    url: str
    path: str
    method: str = "GET"
    evidence: str = ""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    final_url: str = ""


@dataclass
class CrawlResult:
    seed_url: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)


class EndpointCrawler:
    """Lightweight crawler with pluggable discovery strategies."""

    def __init__(self, max_depth: int = 2, max_endpoints: int = 100):
        self.max_depth = max_depth
        self.max_endpoints = max_endpoints
        self._visited_urls: set[str] = set()

    def _fetch(self, client: httpx.Client, url: str, evidence: str) -> DiscoveredEndpoint:
        parsed = urlparse(url)
        try:
            response = client.get(url)
            body = response.text if response.text else ""
            headers = {key.lower(): value for key, value in response.headers.items()}
            return DiscoveredEndpoint(
                url=url,
                path=parsed.path or "/",
                evidence=evidence,
                status_code=response.status_code,
                headers=headers,
                body=body,
                final_url=str(response.url),
            )
        except httpx.HTTPError as exc:
            return DiscoveredEndpoint(url=url, path=parsed.path or "/", evidence=f"{evidence}: {exc}")

    def _parse_html(self, html_body: str, root: str) -> list[str]:
        """Extract URLs from HTML using BeautifulSoup."""
        urls = set()
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            
            # Extract from <a href>
            for tag in soup.find_all('a', href=True):
                href = tag.get('href', '').strip()
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    full_url = urljoin(root, href)
                    urls.add(full_url)
            
            # Extract from <form action>
            for tag in soup.find_all('form', action=True):
                action = tag.get('action', '').strip()
                if action:
                    full_url = urljoin(root, action)
                    urls.add(full_url)
            
            # Extract from <script src>
            for tag in soup.find_all('script', src=True):
                src = tag.get('src', '').strip()
                if src:
                    full_url = urljoin(root, src)
                    urls.add(full_url)
            
            # Extract from <img src> and other resources
            for tag_name in ['img', 'link', 'source']:
                for tag in soup.find_all(tag_name, src=True):
                    src = tag.get('src', '').strip()
                    if src:
                        full_url = urljoin(root, src)
                        urls.add(full_url)
            
            # Extract from <link href>
            for tag in soup.find_all('link', href=True):
                href = tag.get('href', '').strip()
                if href and not href.startswith(('#', 'data:')):
                    full_url = urljoin(root, href)
                    urls.add(full_url)
        except Exception:
            pass
        
        return sorted(urls)

    def _extract_js_routes(self, js_body: str, root: str) -> list[str]:
        """Mine API routes from JavaScript source code."""
        routes = set()
        
        # Patterns for common API route definitions
        patterns = [
            r'["\']([/a-zA-Z0-9\-_.]*?/api[/a-zA-Z0-9\-_.]*?)["\']',  # /api/* routes
            r'["\']([/a-zA-Z0-9\-_.]*?/v[0-9]+[/a-zA-Z0-9\-_.]*?)["\']',  # /v1, /v2 versioned routes
            r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',  # endpoint = "/path"
            r'url\s*[=:]\s*["\']([^"\']+)["\']',  # url = "/path"
            r'path\s*[=:]\s*["\']([^"\']+)["\']',  # path = "/path"
            r'route\s*[=:]\s*["\']([^"\']+)["\']',  # route = "/path"
            r'fetch\s*\(\s*["\']([^"\']+)["\']',  # fetch("/path"
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',  # axios.get("/path"
            r'jquery\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',  # jQuery.ajax("/path"
            r'\$\.ajax\s*\(\s*\{[^}]*url\s*[=:]\s*["\']([^"\']+)["\']',  # $.ajax({url: "/path"
            r'XMLHttpRequest[^)]*\.open\s*\(\s*["\']GET["\'][^,]*,\s*["\']([^"\']+)["\']',  # xhr.open("GET", "/path"
            r'["\']([/a-zA-Z0-9\-_.]*?/admin[/a-zA-Z0-9\-_.]*?)["\']',  # /admin routes
            r'["\']([/a-zA-Z0-9\-_.]*?/users?[/a-zA-Z0-9\-_.]*?)["\']',  # /users, /user routes
            r'["\']([/a-zA-Z0-9\-_.]*?/auth[/a-zA-Z0-9\-_.]*?)["\']',  # /auth routes
            r'["\']([/a-zA-Z0-9\-_.]*?/data[/a-zA-Z0-9\-_.]*?)["\']',  # /data routes
        ]
        
        for pattern in patterns:
            for match in re.findall(pattern, js_body, flags=re.IGNORECASE):
                if match and len(match) > 1:  # Filter out single chars
                    # Normalize the route
                    route = match.strip().strip('"\'')
                    if route.startswith('/'):
                        routes.add(urljoin(root, route))
        
        return sorted(routes)

    def _extract_all_urls(self, body: str, root: str) -> list[str]:
        """Extract URLs from both HTML and inline JavaScript."""
        urls = set()
        
        # Try parsing as HTML
        urls.update(self._parse_html(body, root))
        
        # Also mine JS routes from the body
        urls.update(self._extract_js_routes(body, root))
        
        return sorted(urls)

    def _is_same_origin(self, url: str, root: str) -> bool:
        """Check if URL is same origin as root."""
        parsed = urlparse(url)
        root_parsed = urlparse(root)
        return parsed.netloc == root_parsed.netloc

    def _should_crawl(self, url: str, root: str) -> bool:
        """Determine if URL should be crawled."""
        if url in self._visited_urls:
            return False
        
        parsed = urlparse(url)
        
        # Skip non-HTTP(S)
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Skip different origins
        if not self._is_same_origin(url, root):
            return False
        
        # Skip static assets
        static_exts = ('.js', '.css', '.png', '.jpg', '.gif', '.ico', '.woff', '.ttf', '.svg')
        if any(parsed.path.endswith(ext) for ext in static_exts):
            return False
        
        # Skip common non-endpoint paths
        skip_patterns = [r'^.*\.(pdf|zip|tar|gz|exe|dmg)$', r'^.*#.*']
        if any(re.match(pattern, parsed.path) for pattern in skip_patterns):
            return False
        
        return True

    def crawl(self, seed_url: str) -> CrawlResult:
        parsed = urlparse(seed_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        endpoints: list[DiscoveredEndpoint] = []
        to_visit = [seed_url]
        current_depth = 0
        common_paths = [
            "/api", "/api/v1", "/api/v2", "/health", "/login", "/status",
            "/robots.txt", "/.well-known/security.txt", "/admin", "/users",
            "/auth", "/data", "/graphql", "/rest"
        ]

        with httpx.Client(follow_redirects=True, timeout=15.0, headers={"User-Agent": "CAWASMA/1.0"}) as client:
            # Start with seed URL
            if not self._should_crawl(seed_url, root):
                return CrawlResult(seed_url=seed_url, endpoints=endpoints)
            
            seed_endpoint = self._fetch(client, seed_url, "seed")
            endpoints.append(seed_endpoint)
            self._visited_urls.add(seed_url)
            
            # Queue initial discovery URLs
            discovered = set()
            if seed_endpoint.body:
                discovered.update(self._extract_all_urls(seed_endpoint.body, root))
            
            # Add common paths
            discovered.update([urljoin(root, path) for path in common_paths])
            
            # BFS crawl with depth limiting
            queue = [(url, 0) for url in discovered]
            
            while queue and len(endpoints) < self.max_endpoints:
                url, depth = queue.pop(0)
                
                if depth > self.max_depth:
                    continue
                
                if not self._should_crawl(url, root):
                    continue
                
                evidence = ""
                if url.startswith(root) and urlparse(url).path in common_paths:
                    evidence = "wordlist"
                else:
                    evidence = f"link-discovery-depth{depth}"
                
                endpoint = self._fetch(client, url, evidence)
                endpoints.append(endpoint)
                self._visited_urls.add(url)
                
                # Extract new URLs from this endpoint if we can crawl deeper
                if depth < self.max_depth and endpoint.body:
                    new_urls = self._extract_all_urls(endpoint.body, root)
                    for new_url in new_urls:
                        if self._should_crawl(new_url, root):
                            queue.append((new_url, depth + 1))

        return CrawlResult(seed_url=seed_url, endpoints=endpoints)
