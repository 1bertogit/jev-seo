"""Focused offline coverage for the bounded hosted crawler boundary."""
from __future__ import annotations

import gzip
import os
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jevseo import crawl
from jevseo.crawl import Fetcher, MAX_BODY_BYTES, MAX_TOTAL_BYTES, read_sitemaps, validate_public_url
from jevseo.env import secret
from jevseo.parse import parse_page


def _dns(*addresses):
    return [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]


class FakeResponse:
    def __init__(self, url="https://example.org/", *, status=200, headers=None, chunks=()):
        self.url = url
        self.status_code = status
        self.headers = headers or {"content-type": "text/plain"}
        self.history = []
        self.elapsed = SimpleNamespace(total_seconds=lambda: 0.001)
        self._chunks = list(chunks)
        self.content = b"".join(self._chunks)
        self.text = self.content.decode("utf-8", "replace")
        self.reads = 0
        self.closed = False
        self.is_redirect = 300 <= status < 400

    def iter_content(self, chunk_size=1):
        self.reads += 1
        for chunk in self._chunks:
            yield chunk

    def close(self):
        self.closed = True


class HostedFetchTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "1", "JEVSEO_EGRESS_PROXY": "http://egress.invalid:8080"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_missing_or_invalid_proxy_fails_closed(self):
        with mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "1"}, clear=True):
            with self.assertRaises(ValueError):
                Fetcher()
        for proxy in ("http://egress.invalid", "http://user:pass@egress.invalid:8080", "http://egress.invalid:8080/path?x=1", "http://egress.invalid:70000"):
            with self.subTest(proxy=proxy), mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "1", "JEVSEO_EGRESS_PROXY": proxy}, clear=True):
                with self.assertRaises(ValueError):
                    Fetcher()

    def test_hosted_session_ignores_environment_proxy_bypass(self):
        fetcher = Fetcher()
        self.assertFalse(fetcher.session.trust_env)
        self.assertEqual(fetcher.session.proxies, {"http": "http://egress.invalid:8080", "https": "http://egress.invalid:8080"})

    def test_public_url_rejects_private_cgnat_ipv6_mixed_and_empty_dns(self):
        for addresses in (("192.168.1.2",), ("100.64.0.1",), ("2001:db8::1",), ("224.0.0.1",), ("ff02::1",), ("8.8.8.8", "10.0.0.1"), ()):
            with self.subTest(addresses=addresses), mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns(*addresses)):
                with self.assertRaises(ValueError):
                    validate_public_url("https://example.org/path")
        with mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("::ffff:192.168.1.2")):
            with self.assertRaises(ValueError):
                validate_public_url("https://example.org/path")
        for address in ("::ffff:224.0.0.1", "64:ff9b::a00:1", "2002:0a00:0101::1", "2001:0000:4136:e378:8000:63bf:3fff:fdd2"):
            with self.subTest(address=address), mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns(address)):
                with self.assertRaises(ValueError):
                    validate_public_url("https://example.org/path")
        with mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("::ffff:8.8.8.8")):
            self.assertEqual(validate_public_url("https://example.org/path"), "https://example.org/path")

    def test_public_url_canonicalizes_and_rejects_unsafe_forms(self):
        with mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")):
            self.assertEqual(validate_public_url("HTTPS://Example.org/a/"), "https://example.org/a")
        for url in ("ftp://example.org", "https://user@example.org", "https://example.org:8080", "https://example.org\n/x", "https://" + "a" * 2040 + ".org"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_public_url(url)

    def test_dns_is_rechecked_for_each_fetch(self):
        responses = [FakeResponse(chunks=[b"one"]), FakeResponse(chunks=[b"two"])]
        fetcher = Fetcher()
        with mock.patch.object(fetcher.session, "request", side_effect=responses) as request, mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")) as dns:
            self.assertIsNotNone(fetcher.get("https://example.org/one"))
            self.assertIsNotNone(fetcher.get("https://example.org/two"))
        self.assertEqual(request.call_count, 2)
        self.assertEqual(dns.call_count, 2)

    def test_private_redirect_is_blocked_and_original_response_closed(self):
        redirect = FakeResponse(status=302, headers={"location": "https://private.example/", "content-type": "text/plain"})
        fetcher = Fetcher()
        with mock.patch("jevseo.crawl.socket.getaddrinfo", side_effect=[_dns("8.8.8.8"), _dns("192.168.1.2")]), mock.patch.object(fetcher.session, "request", return_value=redirect) as request:
            self.assertIsNone(fetcher.get("https://example.org/"))
        self.assertEqual(request.call_count, 1)
        self.assertTrue(redirect.closed)

    def test_request_cap_stops_before_the_next_socket_request(self):
        fetcher = Fetcher()
        response = FakeResponse(chunks=[b"ok"])
        with mock.patch("jevseo.crawl.MAX_REQUESTS", 1), mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")), mock.patch.object(fetcher.session, "request", return_value=response) as request:
            self.assertIsNotNone(fetcher.get("https://example.org/1"))
            self.assertIsNone(fetcher.get("https://example.org/2"))
        self.assertEqual(request.call_count, 1)
        self.assertTrue(fetcher.limit_details()["hit_request_cap"])

    def test_streamed_body_cap_closes_without_success(self):
        response = FakeResponse(chunks=[b"a" * MAX_BODY_BYTES, b"b"])
        fetcher = Fetcher()
        with mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")), mock.patch.object(fetcher.session, "request", return_value=response):
            self.assertIsNone(fetcher.get("https://example.org/"))
        self.assertTrue(response.closed)
        self.assertTrue(fetcher.limit_details()["hit_body_cap"])

    def test_compressed_response_is_rejected_before_read(self):
        response = FakeResponse(headers={"content-encoding": "gzip"})
        fetcher = Fetcher()
        with mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")), mock.patch.object(fetcher.session, "request", return_value=response):
            self.assertIsNone(fetcher.get("https://example.org/"))
        self.assertEqual(response.reads, 0)
        self.assertTrue(response.closed)

    def test_total_body_cap_is_atomic_and_visible(self):
        fetcher = Fetcher()
        first = FakeResponse(chunks=[b"abc"])
        second = FakeResponse(chunks=[b"def"])
        with mock.patch("jevseo.crawl.MAX_TOTAL_BYTES", 5), mock.patch("jevseo.crawl.socket.getaddrinfo", return_value=_dns("8.8.8.8")), mock.patch.object(fetcher.session, "request", side_effect=[first, second]):
            self.assertIsNotNone(fetcher.get("https://example.org/1"))
            self.assertIsNone(fetcher.get("https://example.org/2"))
        self.assertTrue(fetcher.limit_details()["hit_total_bytes_cap"])
        self.assertTrue(second.closed)

    def test_gzip_sitemap_decompression_has_output_cap(self):
        payload = gzip.compress(b"x" * (10 * 1024 * 1024 + 1))
        response = SimpleNamespace(status_code=200, content=payload)
        fetcher = Fetcher()
        with mock.patch.object(fetcher, "get", return_value=response):
            out = read_sitemaps(fetcher, ["https://example.org/sitemap.xml.gz"])
        self.assertEqual(out["files"][0]["error"], "sitemap decompression limit exceeded")
        self.assertIn("sitemap decompression limit exceeded", fetcher.limit_details()["reasons"])

    def test_hosted_forces_no_renderer_and_marks_js_dependent_pages(self):
        html = "<html><head><title>Title</title></head><body><main><p>short</p></main><script></script><script></script><script></script></body></html>"

        class CrawlFetcher:
            hosted = True
            requests = 0

            def __init__(self):
                self.limit_details = lambda: {"max_requests": 300, "max_body_bytes": MAX_BODY_BYTES, "max_total_bytes": MAX_TOTAL_BYTES, "requests_used": 1, "bytes_used": len(html), "hit_request_cap": False, "hit_body_cap": False, "hit_total_bytes_cap": False, "reasons": []}

            def get(self, url, **_):
                self.requests += 1
                return FakeResponse(url, headers={"content-type": "text/html"}, chunks=[html.encode()])

            def head(self, _):
                return 200

        class Robots:
            present = False

            def can_fetch(self, *_):
                return True

        robots = {"url": "https://example.org/robots.txt", "status": 404, "present": False, "sitemaps": [], "crawl_delay": None, "disallow_all": False, "search_bots": {}, "ai_bots": {}, "ai_bots_named": [], "_parser": Robots()}
        with mock.patch.object(crawl, "Fetcher", CrawlFetcher), mock.patch.object(crawl, "public_host", return_value=True), mock.patch.object(crawl, "read_robots", return_value=robots), mock.patch.object(crawl, "read_sitemaps", return_value={"files": [], "urls": [], "total_urls": 0}), mock.patch.object(crawl, "Renderer", side_effect=AssertionError("hosted renderer launched")):
            result = crawl.crawl("https://example.org/", render_mode="always", max_pages=1, time_budget=1, log=lambda *_: None)
        self.assertEqual(result["render"]["mode"], "never")
        self.assertFalse(result["pages"][0]["rendered"])
        self.assertTrue(result["pages"][0]["js_dependent"])


class EnvironmentAndParserTests(unittest.TestCase):
    def test_hosted_secret_does_not_touch_fallback_files(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("SECRET_FROM_FILE=value\n")
            fallback = handle.name
        try:
            with mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "1", "JEVSEO_ENV_FILE": fallback}, clear=True), mock.patch("jevseo.env.Path.is_file", side_effect=AssertionError("fallback file touched")):
                self.assertIsNone(secret("SECRET_FROM_FILE"))
        finally:
            os.unlink(fallback)

    def test_ordinary_parser_keeps_body_analysis_and_caps_reader_fields(self):
        title = "Title " * 100
        heading = "Heading " * 100
        html = "<html><head><title>" + title + "</title><meta name='description' content='" + "D" * 3000 + "'></head><body><main><h1>" + heading + "</h1><p>Hello world</p></main></body></html>"
        page = parse_page("https://example.org/", html, "example.org")
        self.assertEqual(len(page["title"]), 512)
        self.assertEqual(len(page["h1"][0]), 512)
        self.assertEqual(len(page["meta_description"]), 2048)
        self.assertEqual(page["word_count"], 102)
        self.assertGreater(len(page["text_excerpt"]), 512)


if __name__ == "__main__":
    unittest.main()
