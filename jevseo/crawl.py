"""Live, polite crawl from a homepage: robots.txt, sitemaps, BFS over internal links.

The crawler stays on the submitted host (www and apex count as one), honours
robots.txt and Crawl-delay for its own user agent, refuses private network
targets, and renders pages with a headless browser only when raw HTML is
missing the visible content.
"""
from __future__ import annotations

import gzip
import ipaddress
import io
import os
import random
import re
import socket
import string
import threading
import time
import urllib.robotparser
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from lxml import etree

from jevseo import USER_AGENT
from jevseo.env import hosted_mode
from jevseo.parse import host_key, normalize_url, parse_page

TIMEOUT = 20
MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REQUESTS = 300
MAX_SITEMAP_DECOMPRESSED_BYTES = 10 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
NAT64_PREFIXES = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
SKIP_EXT = re.compile(r"\.(jpe?g|png|gif|webp|avif|svg|ico|pdf|zip|gz|mp4|mp3|webm|woff2?|ttf|css|js|xml|json|txt|md|markdown|docx?|xlsx?|pptx?)$", re.I)
AI_BOTS = ["GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "Claude-SearchBot", "PerplexityBot", "Google-Extended", "Applebot-Extended", "CCBot", "Bytespider"]
SEARCH_BOTS = ["Googlebot", "Bingbot"]
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _global_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    # Be explicit for runtimes where is_global on an IPv4-mapped IPv6 address
    # does not inherit the mapped IPv4 address' classification.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_multicast or address.is_unspecified or address.is_reserved or address.is_loopback or address.is_link_local:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        # These standard transition prefixes encode an IPv4 destination. The
        # prefix itself is not an Internet destination, so fail closed rather
        # than trusting a globally classified IPv6 wrapper.
        if any(address in prefix for prefix in NAT64_PREFIXES):
            return False
        embedded = []
        if address.sixtofour:
            embedded.append(address.sixtofour)
        if address.teredo:
            embedded.extend(address.teredo)
        if embedded and not all(_global_address(str(ipv4)) for ipv4 in embedded):
            return False
    if address.is_private:
        return False
    return address.is_global


def public_host(host: str) -> bool:
    """Resolve every returned A/AAAA address and require all of them global."""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, socket.gaierror):
        return False
    addresses = []
    for info in infos:
        if info[0] not in (socket.AF_INET, socket.AF_INET6):
            continue
        try:
            addresses.append(info[4][0])
        except (IndexError, TypeError):
            return False
    return bool(addresses) and all(_global_address(address) for address in addresses)


def validate_public_url(url: str) -> str:
    """Canonicalize an HTTP(S) URL whose complete DNS answer is public."""
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("invalid public URL")
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https") or not parsed.netloc or "@" in parsed.netloc:
            raise ValueError("invalid public URL")
        if parsed.username is not None or parsed.password is not None or not parsed.hostname or parsed.netloc.endswith(":"):
            raise ValueError("invalid public URL")
        port = parsed.port
        if port is not None and port not in (80, 443):
            raise ValueError("invalid public URL")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc += f":{port}"
        canonical = normalize_url(parsed._replace(scheme=scheme, netloc=netloc).geturl())
    except (UnicodeError, ValueError, TypeError):
        raise ValueError("invalid public URL") from None
    if len(canonical) > MAX_URL_LENGTH or not public_host(host):
        raise ValueError("invalid public URL")
    return canonical


def validate_proxy_url(url: str) -> str:
    """Validate trusted worker proxy configuration without resolving its host."""
    if not isinstance(url, str) or not url or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("invalid hosted egress proxy")
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or "@" in parsed.netloc:
            raise ValueError
        if parsed.username is not None or parsed.password is not None or not parsed.hostname or parsed.port is None or not 1 <= parsed.port <= 65535:
            raise ValueError
        if "?" in url or "#" in url or parsed.path not in ("", "/"):
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        netloc = f"[{host}]" if ":" in host else host
        proxy = f"{parsed.scheme.lower()}://{netloc}:{parsed.port}"
    except (UnicodeError, ValueError, TypeError):
        raise ValueError("invalid hosted egress proxy") from None
    return proxy


class Fetcher:
    def __init__(self, delay: float = 0.0):
        self.session = requests.Session()
        self.hosted = hosted_mode()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en;q=0.9,*;q=0.5"})
        self.proxy = None
        if self.hosted:
            try:
                self.proxy = validate_proxy_url(os.environ["JEVSEO_EGRESS_PROXY"])
            except (KeyError, ValueError):
                raise ValueError("hosted mode requires a valid egress proxy") from None
            self.session.trust_env = False
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
            self.session.headers.update({"Accept-Encoding": "identity"})
        self.delay = delay
        self.lock = threading.Lock()
        self.last = 0.0
        self.requests = 0
        self.bytes = 0
        self._limit_reasons: list[str] = []
        self._hit_request_cap = False
        self._hit_body_cap = False
        self._hit_total_bytes_cap = False
        self._hit_sitemap_cap = False

    def _note_limit(self, reason: str) -> None:
        with self.lock:
            if reason not in self._limit_reasons:
                self._limit_reasons.append(reason)
            if reason == "request cap exceeded":
                self._hit_request_cap = True
            elif reason == "response body limit exceeded":
                self._hit_body_cap = True
            elif reason == "total response bytes limit exceeded":
                self._hit_total_bytes_cap = True
            elif reason == "sitemap decompression limit exceeded":
                self._hit_sitemap_cap = True

    def _pace(self) -> bool:
        with self.lock:
            if self.hosted and self.requests >= MAX_REQUESTS:
                if "request cap exceeded" not in self._limit_reasons:
                    self._limit_reasons.append("request cap exceeded")
                self._hit_request_cap = True
                return False
            self.requests += 1
            if self.delay:
                wait = self.last + self.delay - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                self.last = time.monotonic()
        return True

    def _consume_bytes(self, size: int) -> bool:
        with self.lock:
            if self.bytes + size > MAX_TOTAL_BYTES:
                if "total response bytes limit exceeded" not in self._limit_reasons:
                    self._limit_reasons.append("total response bytes limit exceeded")
                self._hit_total_bytes_cap = True
                return False
            self.bytes += size
            return True

    def _read_hosted_response(self, response: requests.Response) -> requests.Response | None:
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding and encoding != "identity":
            self._note_limit("non-identity content encoding rejected")
            response.close()
            return None
        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=STREAM_CHUNK_BYTES):
                if not chunk:
                    continue
                chunk = bytes(chunk)
                if len(body) + len(chunk) > MAX_BODY_BYTES:
                    self._note_limit("response body limit exceeded")
                    response.close()
                    return None
                if not self._consume_bytes(len(chunk)):
                    response.close()
                    return None
                body.extend(chunk)
        except (OSError, requests.RequestException, ValueError, TypeError):
            response.close()
            return None
        response._content = bytes(body)
        response._content_consumed = True
        response.close()
        return response

    def limit_details(self) -> dict:
        with self.lock:
            reasons = list(self._limit_reasons)
            return {
                "max_requests": MAX_REQUESTS,
                "max_body_bytes": MAX_BODY_BYTES,
                "max_total_bytes": MAX_TOTAL_BYTES,
                "requests_used": self.requests,
                "bytes_used": self.bytes,
                "hit_request_cap": self._hit_request_cap,
                "hit_body_cap": self._hit_body_cap,
                "hit_total_bytes_cap": self._hit_total_bytes_cap,
                "hit_sitemap_decompression_cap": self._hit_sitemap_cap,
                "reasons": reasons,
            }

    def _send(self, method: str, url: str, **kw) -> requests.Response | None:
        """Follow redirects by hand so every hop is DNS-checked and bounded."""
        history = []
        for _ in range(10):
            try:
                url = validate_public_url(url)
            except ValueError:
                return None
            if not self._pace():
                return None
            request_kw = dict(kw)
            if self.hosted:
                headers = dict(request_kw.get("headers") or {})
                for key in list(headers):
                    if key.lower() == "accept-encoding":
                        del headers[key]
                headers["Accept-Encoding"] = "identity"
                request_kw["headers"] = headers
                request_kw["stream"] = True
                request_kw["proxies"] = {"http": self.proxy, "https": self.proxy}
            try:
                r = self.session.request(method, url, timeout=TIMEOUT, allow_redirects=False, **request_kw)
            except (requests.RequestException, ValueError):
                return None
            if self.hosted:
                r = self._read_hosted_response(r)
                if r is None:
                    return None
            is_redirect = getattr(r, "is_redirect", 300 <= getattr(r, "status_code", 0) < 400)
            if is_redirect and r.headers.get("location"):
                history.append(r)
                r.close()
                url = urljoin(r.url, r.headers["location"])
                continue
            r.history = history
            return r
        return None

    def get(self, url: str, **kw) -> requests.Response | None:
        return self._send("GET", url, **kw)

    def head(self, url: str) -> int | None:
        r = self._send("HEAD", url)
        # Some servers (support.google.com among them) fail HEAD but serve GET: never call a link broken on HEAD alone.
        if r is None or r.status_code >= 400:
            r = self._send("GET", url, stream=True)
            if r is not None:
                r.close()
        return r.status_code if r is not None else None


def read_robots(fetcher: Fetcher, origin: str) -> dict:
    url = origin + "/robots.txt"
    r = fetcher.get(url)
    body = r.text if r is not None and r.status_code == 200 and "html" not in r.headers.get("content-type", "") else ""
    parser = urllib.robotparser.RobotFileParser()
    parser.parse(body.splitlines())
    sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
    probe = origin + "/"
    return {
        "url": url,
        "status": r.status_code if r is not None else None,
        "present": bool(body),
        "bytes": len(body.encode()),
        "sitemaps": sitemaps,
        "crawl_delay": parser.crawl_delay(USER_AGENT.split("/")[0]) or parser.crawl_delay("*"),
        "disallow_all": not parser.can_fetch("*", probe) if body else False,
        "search_bots": {b: parser.can_fetch(b, probe) for b in SEARCH_BOTS},
        "ai_bots": {b: parser.can_fetch(b, probe) for b in AI_BOTS},
        "ai_bots_named": [b for b in AI_BOTS if re.search(rf"(?im)^\s*user-agent:\s*{re.escape(b)}\s*$", body)],
        "_parser": parser,
    }


def read_sitemaps(fetcher: Fetcher, urls: list[str], limit: int = 5000) -> dict:
    found, seen, out = [], set(), []
    queue = deque(urls)
    while queue and len(seen) < 25:
        sm = queue.popleft()
        if sm in seen:
            continue
        seen.add(sm)
        r = fetcher.get(sm)
        entry = {"url": sm, "status": r.status_code if r is not None else None, "urls": 0, "error": None, "lastmod": 0}
        if r is None or r.status_code != 200:
            entry["error"] = "unreachable" if r is None else f"HTTP {r.status_code}"
            out.append(entry)
            continue
        content = r.content
        if sm.endswith(".gz") or content[:2] == b"\x1f\x8b":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
                    content = stream.read(MAX_SITEMAP_DECOMPRESSED_BYTES + 1)
                if len(content) > MAX_SITEMAP_DECOMPRESSED_BYTES:
                    entry["error"] = "sitemap decompression limit exceeded"
                    fetcher._note_limit("sitemap decompression limit exceeded")
                    out.append(entry)
                    continue
            except (OSError, EOFError):
                pass
        try:
            root = etree.fromstring(content, parser=etree.XMLParser(recover=True, resolve_entities=False, no_network=True))
        except etree.XMLSyntaxError:
            root = None
        if root is None:
            entry["error"] = "not valid XML"
            out.append(entry)
            continue
        tag = etree.QName(root).localname
        # "{*}" matches elements in any namespace and skips comments and processing instructions.
        locs = [el.text.strip() for el in root.iter("{*}loc") if el.text]
        entry["lastmod"] = sum(1 for _ in root.iter("{*}lastmod"))
        entry["type"] = tag
        if tag == "sitemapindex":
            queue.extend(locs)
            entry["children"] = len(locs)
        else:
            entry["urls"] = len(locs)
            found.extend(locs)
        out.append(entry)
    unique = list(dict.fromkeys(normalize_url(u) for u in found))
    return {"files": out, "urls": unique[:limit], "total_urls": len(unique)}


class Renderer:
    """Headless Chromium through Playwright, started lazily and only if needed."""

    def __init__(self):
        self._pw = self._browser = None
        self.available = None

    def render(self, url: str) -> str | None:
        try:
            if self._browser is None:
                from playwright.sync_api import sync_playwright

                self._pw = sync_playwright().start()
                self._browser = self._pw.chromium.launch()
                self.available = True
            page = self._browser.new_page(user_agent=USER_AGENT)
            page.goto(url, wait_until="networkidle", timeout=30000)
            html = page.content()
            page.close()
            return html
        except Exception:  # noqa: BLE001  rendering is best effort; raw HTML remains the evidence
            self.available = False
            return None

    def close(self):
        try:
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()


def fetch_page(fetcher: Fetcher, url: str, site_host: str) -> dict:
    """One page fetch; any parser failure becomes an error record, never a crashed crawl."""
    try:
        return _fetch_page(fetcher, url, site_host)
    except Exception as err:  # noqa: BLE001
        return {"url": url, "fetched_at": now(), "status": None, "error": f"parse failure: {type(err).__name__}"}


def _fetch_page(fetcher: Fetcher, url: str, site_host: str) -> dict:
    started = time.monotonic()
    r = fetcher.get(url)
    elapsed = round((time.monotonic() - started) * 1000)
    rec = {"url": url, "fetched_at": now(), "fetch_ms": elapsed}
    if r is None:
        return rec | {"status": None, "error": "network error or timeout"}
    ctype = r.headers.get("content-type", "")
    rec |= {
        "status": r.status_code,
        "final_url": normalize_url(r.url),
        "redirect_chain": [{"url": h.url, "status": h.status_code} for h in r.history],
        "content_type": ctype.split(";")[0].strip(),
        "bytes": len(r.content),
        "ttfb_ms": round(r.elapsed.total_seconds() * 1000),
        "x_robots": r.headers.get("x-robots-tag"),
        "headers": {h: r.headers.get(h) for h in SECURITY_HEADERS if r.headers.get(h)},
        "rendered": False,
        "js_dependent": False,
    }
    if r.status_code != 200 or "html" not in ctype:
        return rec
    facts = parse_page(rec["final_url"], decode(r), site_host)
    rec["raw_word_count"] = facts["word_count"]
    result = rec | facts
    if getattr(fetcher, "hosted", False) and needs_render(result):
        result["js_dependent"] = True
    return result


def decode(r: requests.Response) -> str:
    """Header charset first, then the page's own meta charset, then UTF-8. Never requests' Latin-1 default."""
    if "charset=" in r.headers.get("content-type", "").lower():
        return r.text
    head = r.content[:4096].decode("ascii", "ignore")
    m = re.search(r"""<meta[^>]+charset=["']?([\w-]+)""", head, re.I)
    for enc in ([m.group(1)] if m else []) + ["utf-8"]:
        try:
            return r.content.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return r.content.decode("utf-8", "replace")


def needs_render(rec: dict) -> bool:
    return rec.get("status") == 200 and "raw_word_count" in rec and rec["raw_word_count"] < 60 and rec.get("script_count", 0) >= 3


def rerender(rec: dict, renderer: Renderer, site_host: str) -> dict:
    """Main-thread only: Playwright's sync objects are bound to their creating thread."""
    html = renderer.render(rec["final_url"])
    if not html:
        return rec
    facts = parse_page(rec["final_url"], html, site_host)
    if facts["word_count"] <= rec.get("word_count", 0):
        return rec
    return rec | facts | {"rendered": True, "js_dependent": True}


def crawl(start_url: str, max_pages: int = 60, max_depth: int = 5, workers: int = 6, render_mode: str = "auto", time_budget: int = 600, log=print) -> dict:
    if not re.match(r"^https?://", start_url):
        start_url = "https://" + start_url
    fetcher = Fetcher()
    try:
        start = validate_public_url(start_url)
    except ValueError:
        raise SystemExit(f"Refusing to crawl {start_url}: it is not a valid public HTTP(S) URL.") from None

    home = fetcher.get(start)
    if home is None:
        raise SystemExit(f"Could not reach {start}.")
    try:
        final_home = validate_public_url(home.url)
    except ValueError:
        raise SystemExit(f"Refusing to crawl {start}: the final URL is not public.") from None
    origin = f"{urlparse(final_home).scheme}://{urlparse(final_home).netloc}"
    site = host_key(urlparse(final_home).netloc)
    log(f"homepage {start} -> {final_home} (HTTP {home.status_code})")

    robots = read_robots(fetcher, origin)
    parser = robots.pop("_parser")
    if robots["crawl_delay"]:
        fetcher.delay = min(float(robots["crawl_delay"]), 5.0)
        workers = 1
    sitemap_urls = robots["sitemaps"] or [origin + "/sitemap.xml"]
    sitemaps = read_sitemaps(fetcher, sitemap_urls)
    in_sitemap = {u for u in sitemaps["urls"] if host_key(urlparse(u).netloc) == site}
    log(f"robots.txt {'found' if robots['present'] else 'missing'}; sitemap URLs {sitemaps['total_urls']}")

    # Site-level probes: HTTP to HTTPS, host variant, soft 404, llms.txt
    probes = {}
    http_home = "http://" + urlparse(final_home).netloc + "/"
    r = fetcher.get(http_home)
    probes["http_to_https"] = bool(r is not None and r.url.startswith("https://"))
    probes["http_redirect_status"] = r.history[0].status_code if r is not None and r.history else None
    alt = urlparse(final_home).netloc
    alt = alt[4:] if alt.startswith("www.") else "www." + alt
    r = fetcher.get(f"{urlparse(final_home).scheme}://{alt}/")
    probes["host_variant"] = {"host": alt, "status": r.status_code if r is not None else None, "redirect_status": r.history[0].status_code if r is not None and r.history else None, "redirects_to_canonical_host": bool(r is not None and host_key(urlparse(r.url).netloc) == site and urlparse(r.url).netloc == urlparse(final_home).netloc)}
    junk = "".join(random.choices(string.ascii_lowercase, k=14))
    r = fetcher.get(f"{origin}/jevseo-{junk}-not-found")
    probes["not_found_status"] = r.status_code if r is not None else None
    r = fetcher.get(origin + "/llms.txt")
    probes["llms_txt"] = bool(r is not None and r.status_code == 200 and "html" not in r.headers.get("content-type", "") and len(r.text.strip()) > 20)

    if fetcher.hosted:
        render_mode = "never"
    renderer = Renderer() if render_mode != "never" else None
    pages: dict[str, dict] = {}
    depth: dict[str, int] = {final_home: 0}
    queue = deque([final_home])
    blocked: list[str] = []
    for u in sorted(in_sitemap, key=len):
        depth.setdefault(u, 99)
    sitemap_seed = deque(sorted(in_sitemap - {final_home}, key=len))
    deadline = time.monotonic() + time_budget

    def allowed(u: str) -> bool:
        return parser.can_fetch(USER_AGENT, u) if robots["present"] else True

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while (queue or sitemap_seed) and len(pages) < max_pages and time.monotonic() < deadline:
            batch = []
            while queue and len(batch) + len(pages) < max_pages and len(batch) < workers * 2:
                u = queue.popleft()
                if u in pages or SKIP_EXT.search(urlparse(u).path):
                    continue
                if not allowed(u):
                    blocked.append(u)
                    pages[u] = {"url": u, "status": None, "error": "blocked by robots.txt", "depth": depth.get(u)}
                    continue
                batch.append(u)
                pages[u] = {}
            if not batch:
                # Link discovery ran dry: fall back to sitemap URLs the links never reached.
                while sitemap_seed and len(queue) < workers * 2:
                    u = sitemap_seed.popleft()
                    if u not in pages:
                        queue.append(u)
                continue
            results = list(pool.map(lambda u: fetch_page(fetcher, u, site), batch))
            if renderer and renderer.available is not False:
                results = [rerender(rec, renderer, site) if render_mode == "always" and rec.get("status") == 200 and "word_count" in rec or needs_render(rec) else rec for rec in results]
            for rec in results:
                u = rec["url"]
                rec["depth"] = depth.get(u, 99)
                target = rec.get("final_url") or u
                if target != u:
                    # Keep the redirect as its own record; the content belongs to the target only.
                    pages[u] = {k: rec.get(k) for k in ("url", "status", "final_url", "redirect_chain", "fetched_at", "depth")} | {
                        "kind": "redirect",
                        "status": rec["redirect_chain"][0]["status"] if rec.get("redirect_chain") else rec.get("status"),
                        "final_status": rec.get("status"),
                        "in_sitemap": u in in_sitemap,
                    }
                    if target in pages or host_key(urlparse(target).netloc) != site:
                        continue
                    depth[target] = min(depth.get(target, 99), rec["depth"])
                    rec = rec | {"url": target, "reached_via": u, "depth": depth[target]}
                    u = target
                rec["kind"] = "page"
                rec["in_sitemap"] = u in in_sitemap
                pages[u] = rec
                for link in rec.get("links_internal", []):
                    v = link["url"]
                    if urlparse(v).query and len(pages) > max_pages // 2:
                        continue
                    if v not in depth or depth[v] > rec["depth"] + 1:
                        depth[v] = min(depth.get(v, 99), rec["depth"] + 1)
                    if v not in pages and v not in queue and depth[v] <= max_depth:
                        queue.append(v)
            rendered = sum(1 for p in pages.values() if p.get("rendered"))
            log(f"crawled {len(pages)}/{max_pages} URLs, {len(queue)} queued" + (f", {rendered} rendered with JavaScript" if rendered else ""))
    if renderer:
        renderer.close()
    hit_time = time.monotonic() >= deadline
    hit_cap = sum(1 for p in pages.values() if p.get("kind") != "redirect") >= max_pages or len(pages) >= max_pages

    # Inlinks and link status for internal targets never crawled (bounded HEAD checks).
    inlinks: dict[str, int] = {}
    anchors: dict[str, list[str]] = {}
    for rec in pages.values():
        for link in {l["url"]: l for l in rec.get("links_internal", [])}.values():
            if link["url"] != rec["url"]:
                inlinks[link["url"]] = inlinks.get(link["url"], 0) + 1
                if link["anchor"]:
                    anchors.setdefault(link["url"], []).append(link["anchor"])
    redirect_to = {u: p["final_url"] for u, p in pages.items() if p.get("kind") == "redirect" and p.get("final_url")}
    for src, n in list(inlinks.items()):
        target = redirect_to.get(src)
        if target and target != src:
            inlinks[target] = inlinks.get(target, 0) + n
            anchors.setdefault(target, []).extend(anchors.get(src, []))
    # A link is broken when its final destination fails; robots-blocked targets are unknown, not broken.
    status_of = {}
    for u, p in pages.items():
        if p.get("error") == "blocked by robots.txt":
            status_of[u] = "blocked"
        elif p.get("kind") == "redirect":
            final = p.get("final_status")
            status_of[u] = final if final is None or final >= 400 else p.get("status")
        else:
            status_of[u] = p.get("status")
    log("checking link targets and a sample of outbound links")
    unchecked = [u for u in inlinks if u not in status_of and not SKIP_EXT.search(urlparse(u).path) and allowed(u)][:150]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for u, st in zip(unchecked, pool.map(fetcher.head, unchecked)):
            status_of[u] = st
    externals = list(dict.fromkeys(l["url"] for p in pages.values() for l in p.get("links_external", [])))
    ext_sample = externals[:80]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        ext_status = dict(zip(ext_sample, pool.map(fetcher.head, ext_sample)))
    for p in pages.values():
        u = p.get("url")
        p["inlinks"] = inlinks.get(u, 0)
        p["inlink_anchors"] = sorted(set(anchors.get(u, [])))[:15]

    home_rec = pages.get(final_home, {})
    limit_details = fetcher.limit_details()
    return {
        "input_url": start_url,
        "start_url": start,
        "final_url": final_home,
        "origin": origin,
        "domain": site,
        "https": final_home.startswith("https://"),
        "robots": robots,
        "sitemaps": sitemaps,
        "probes": probes,
        "pages": list(pages.values()),
        "link_status": status_of,
        "external_status": ext_status,
        "external_total": len(externals),
        "blocked_by_robots": blocked,
        "render": {"mode": render_mode, "browser_available": renderer.available if renderer else None, "homepage_rendered": home_rec.get("rendered", False)},
        "requests": fetcher.requests,
        "limits": {"max_pages": max_pages, "max_depth": max_depth, "time_budget_s": time_budget, "hit_page_cap": hit_cap, "hit_time_budget": hit_time, **limit_details},
    }
