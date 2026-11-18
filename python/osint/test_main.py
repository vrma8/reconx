import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from osint.__main__ import censys_hit, download_urlscan_screenshots, dorks, encode_name, gitlab_code_search, linkedin_employee_lead, parse_dns_packet, public_ips, resolve, safe_text, shodan_match, value_after


class OSINTWorkerTests(unittest.TestCase):
    def test_dorks_are_target_scoped(self) -> None:
        queries = dorks("example.com")["queries"]
        self.assertEqual(len(queries), 6)
        self.assertTrue(all("example.com" in query for query in queries))

    def test_whois_value_parser_deduplicates(self) -> None:
        lines = ["Name Server: NS1.EXAMPLE.COM", "name server: NS1.EXAMPLE.COM", "Registrar: Example Registrar"]
        self.assertEqual(value_after(lines, ("name server",)), ["NS1.EXAMPLE.COM"])
        self.assertEqual(value_after(lines, ("registrar",)), ["Example Registrar"])

    def test_dns_packet_parser_extracts_a_record(self) -> None:
        query_id = 321
        question = encode_name("example.com") + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        packet = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer
        records, truncated = parse_dns_packet(packet, query_id)
        self.assertFalse(truncated)
        self.assertEqual(records["a"], ["93.184.216.34"])

    def test_passive_ip_filter_and_redaction(self) -> None:
        self.assertEqual(public_ips(["10.0.0.1", "8.8.8.8", "8.8.8.8"]), ["8.8.8.8"])
        self.assertEqual(safe_text("api_key=do-not-store"), "[REDACTED: potential credential-like content]")

    def test_censys_summary_retains_service_and_certificate_metadata(self) -> None:
        result = censys_hit({
            "ip": "8.8.8.8",
            "labels": ["dns"],
            "services": [{
                "port": 443,
                "service_name": "HTTP",
                "tls": {"certificates": {"leaf_data": {"names": ["www.example.com"]}}},
            }],
        })
        self.assertEqual(result["services"][0]["port"], "443")
        self.assertEqual(result["certificates"], ["www.example.com"])
        self.assertEqual(result["tags"], ["dns"])

    def test_urlscan_screenshot_download_accepts_only_png(self) -> None:
        url = "https://urlscan.io/screenshots/0123456789abcdef0123456789abcdef.png"
        with tempfile.TemporaryDirectory() as directory:
            with patch("osint.__main__.request_bytes", return_value=(200, b"\x89PNG\r\n\x1a\nfixture")):
                result = download_urlscan_screenshots([url], directory)
            artifact = result["artifacts"][0]
            self.assertEqual(artifact["status"], "saved")
            self.assertTrue(artifact["path"].endswith(".png"))
            self.assertTrue(os.path.isfile(artifact["path"]))

    def test_shodan_banner_is_bounded_and_redacted(self) -> None:
        result = shodan_match({"ip_str": "8.8.8.8", "data": "api_key=do-not-store"})
        self.assertEqual(result["banner"], "[REDACTED: potential credential-like content]")

    def test_gitlab_search_emits_redacted_secret_indicator_and_public_email(self) -> None:
        payload = [{"project_id": 42, "path": "config.yml", "url": "https://gitlab.com/demo/project/-/blob/main/config.yml", "data": "email: security@example.com\napi_key: do-not-store"}]
        with patch.dict(os.environ, {"RECONX_GITLAB_TOKEN": "test-token"}, clear=False), patch("osint.__main__.http_json", return_value=payload):
            result = gitlab_code_search("example.com", [])
        self.assertEqual(result["emails"], ["security@example.com"])
        self.assertEqual(result["potential_secret_indicators"][0]["source"], "gitlab_code_search")

    def test_linkedin_public_lead_is_structured_without_scraping(self) -> None:
        lead = linkedin_employee_lead("Ada Lovelace - Security Engineer - Example | LinkedIn", "https://www.linkedin.com/in/ada", "Security engineer at Example")
        self.assertEqual(lead["name"], "Ada Lovelace")
        self.assertEqual(lead["source"], "public_search_result")

    def test_resolve_checks_hibp_after_second_hop_public_email_discovery(self) -> None:
        data = {
            "dns": {"name": "example.com", "a": ["8.8.8.8"], "aaaa": [], "ns": []},
            "whois": {"emails": ["security@example.com"]},
            "certificate_transparency": {"subdomains": []},
            "urlscan": {"results": []},
            "virustotal": {"domain": {}, "ips": {}},
            "shodan": {"domain": {}, "ips": {}, "neighbors": {}},
            "censys": {"domain": [], "ips": {}, "neighbors": {}},
            "github_code_search": {"emails": ["dev@example.com"], "queries": [], "potential_secret_indicators": []},
            "gitlab_code_search": {"emails": [], "queries": [], "potential_secret_indicators": []},
            "search_engine_recon": {"emails": [], "employees": [], "results": [], "potential_secret_indicators": []},
            "securitytrails_dns_history": {},
            "viewdns_history_and_reverse_ip": {},
            "network_ownership": {},
            "dorks": {"queries": []},
            "dns_zone_transfer": {},
            "github_code_search_discovered_emails": {"emails": ["ops@example.com"], "queries": [], "potential_secret_indicators": []},
            "gitlab_code_search_discovered_emails": {"emails": [], "queries": [], "potential_secret_indicators": []},
            "search_engine_recon_discovered_emails": {"emails": [], "employees": [], "results": [], "potential_secret_indicators": []},
            "social_username_enumeration": {},
        }
        hibp_inputs: list[list[str]] = []

        def fake_run_source(name: str, function: object) -> tuple[str, dict[str, object]]:
            if name == "hibp":
                return name, {"status": "ok", "duration_ms": 0, "data": function()}
            return name, {"status": "ok", "duration_ms": 0, "data": data[name]}

        def fake_hibp(emails: list[str]) -> dict[str, object]:
            hibp_inputs.append(emails)
            return {}

        with patch("osint.__main__.run_source", side_effect=fake_run_source), patch("osint.__main__.hibp", side_effect=fake_hibp):
            result = resolve("example.com", ["8.8.8.8"])
        self.assertEqual(result["emails"], ["dev@example.com", "ops@example.com", "security@example.com"])
        self.assertEqual(hibp_inputs, [result["emails"]])


if __name__ == "__main__":
    unittest.main()
