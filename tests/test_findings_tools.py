import unittest

import findings

# Verbatim fragments of output these tools really produced against the lab target.
NMAP = """Starting Nmap 7.991 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00026s latency).

PORT      STATE SERVICE
5005/tcp  open  avt-profile-2
8888/tcp  open  sun-answerbook
9999/tcp  closed unknown
11434/tcp open  ollama

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
"""
FFUF = (
    "\x1b[2K.env                    [Status: 200, Size: 262, Words: 1, Lines: 8, Duration: 31ms]\n"
    "\x1b[2Kadmin                   [Status: 403, Size: 2665, Words: 367, Lines: 81, Duration: 29ms]\n"
)
DALFOX = (
    "11:41AM INF found reflected 1 params\n"
    "11:41AM WRN XSS found 1 XSS\n"
    "[POC][V][GET][inHTML] http://127.0.0.1:5005/search?q=%22%3E%3Csvg%20onload%3Dalert%281%29%3E\n"
)
WAF_NONE = "[*] Checking http://127.0.0.1:5005\n[-] No WAF detected by the generic detection\n"
WAF_FOUND = "[*] Checking http://example.test\n[+] The site http://example.test is behind Cloudflare WAF.\n"
ARJUN = " parameter detected: q, based on: body length\n Parameters found: q\n"
NIKTO = "+ /admin/: Admin login page/section found.\n+ /.env: Environment file found.\n"
CHECKOV = (
    '{"results": {"failed_checks": ['
    '{"check_id": "CKV_AWS_53", "check_name": "Ensure S3 bucket has block public ACLs enabled",'
    ' "file_path": "/main.tf", "severity": null}]}}'
)
TERRASCAN = (
    '{"results": {"violations": [{"rule_name": "s3Versioning",'
    ' "description": "Enabling S3 versioning", "severity": "HIGH", "file": "main.tf"}]}}'
)
TRIVY = (
    '{"Results": [{"Target": "alpine:3.1", "Vulnerabilities": ['
    '{"VulnerabilityID": "CVE-2021-1234", "PkgName": "openssl", "Severity": "HIGH", "Title": "flaw"}]}]}'
)
EXIF = "File Name                       : photo.jpg\nGPS Position                    : 51 deg 30' N\nMIME Type : image/jpeg\n"


class PortScanTests(unittest.TestCase):
    def test_only_open_ports_are_reported(self):
        results = findings.extract("nmap", NMAP)
        self.assertEqual({item["path"] for item in results},
                         {"5005/tcp", "8888/tcp", "11434/tcp"})

    def test_the_service_name_is_carried_into_the_note(self):
        ollama = next(i for i in findings.extract("nmap", NMAP) if i["path"] == "11434/tcp")
        self.assertIn("ollama", ollama["note"])

    def test_rustscan_output_uses_the_same_parser_with_its_own_source(self):
        results = findings.extract("rustscan", NMAP)
        self.assertTrue(results)
        self.assertEqual(results[0]["source"], "rustscan")

    def test_a_port_is_not_reported_twice(self):
        doubled = NMAP + NMAP
        self.assertEqual(len(findings.extract("nmap", doubled)), 3)


class WebToolTests(unittest.TestCase):
    def test_ffuf_control_codes_do_not_corrupt_the_path(self):
        results = findings.extract("ffuf", FFUF)
        self.assertEqual({item["path"] for item in results}, {"/.env", "/admin"})
        env = next(i for i in results if i["path"] == "/.env")
        self.assertEqual((env["status"], env["size"]), (200, 262))
        self.assertIn("credentials", env["note"])

    def test_dalfox_poc_is_reported_as_reflected_not_proven(self):
        result = findings.extract("dalfox", DALFOX)[0]
        self.assertEqual(result["severity"], "high")
        self.assertIn("reflected payload", result["note"])
        self.assertIn("confirm it manually", result["evidence"])

    def test_dalfox_log_lines_are_not_mistaken_for_findings(self):
        self.assertEqual(len(findings.extract("dalfox", DALFOX)), 1)

    def test_nikto_lines_become_findings_with_their_detail(self):
        results = findings.extract("nikto", NIKTO)
        self.assertEqual({item["path"] for item in results}, {"/admin/", "/.env"})
        self.assertIn("Admin login page", results[0]["note"])

    def test_wafw00f_reports_both_outcomes_truthfully(self):
        self.assertIn("no WAF detected", findings.extract("wafw00f", WAF_NONE)[0]["note"])
        self.assertIn("Cloudflare", findings.extract("wafw00f", WAF_FOUND)[0]["note"])

    def test_arjun_rationale_is_not_treated_as_a_parameter(self):
        results = findings.extract("arjun", ARJUN)
        self.assertEqual([item["path"] for item in results], ["?q"])


class CloudToolTests(unittest.TestCase):
    def test_checkov_failed_checks_become_findings(self):
        result = findings.extract("checkov", CHECKOV)[0]
        self.assertEqual(result["path"], "/main.tf")
        self.assertIn("CKV_AWS_53", result["note"])

    def test_terrascan_violations_carry_severity(self):
        result = findings.extract("terrascan", TERRASCAN)[0]
        self.assertEqual(result["severity"], "high")
        self.assertIn("s3Versioning", result["note"])

    def test_trivy_vulnerabilities_name_the_package(self):
        result = findings.extract("trivy", TRIVY)[0]
        self.assertIn("openssl", result["path"])
        self.assertIn("CVE-2021-1234", result["note"])

    def test_malformed_json_yields_nothing_rather_than_raising(self):
        for tool in ("checkov", "terrascan", "trivy"):
            self.assertEqual(findings.extract(tool, "not json at all"), [])


class ForensicsTests(unittest.TestCase):
    def test_only_notable_metadata_is_surfaced(self):
        results = findings.extract("exiftool", EXIF)
        self.assertEqual(len(results), 1)
        self.assertIn("GPS Position", results[0]["note"])
        self.assertEqual(results[0]["path"], "photo.jpg")


class CoverageTests(unittest.TestCase):
    def test_every_extractor_returns_a_list_for_empty_input(self):
        for tool in findings.EXTRACTORS:
            self.assertEqual(findings.extract(tool, ""), [], tool)

    def test_every_finding_has_the_fields_the_report_renders(self):
        samples = {"nmap": NMAP, "ffuf": FFUF, "dalfox": DALFOX, "nikto": NIKTO,
                   "wafw00f": WAF_NONE, "arjun": ARJUN, "checkov": CHECKOV,
                   "terrascan": TERRASCAN, "trivy": TRIVY, "exiftool": EXIF}
        for tool, output in samples.items():
            for item in findings.extract(tool, output):
                for field in ("path", "status", "size", "source"):
                    self.assertIn(field, item, f"{tool} finding is missing {field}")
                self.assertTrue(item["path"], tool)


if __name__ == "__main__":
    unittest.main()


class DeduplicationTests(unittest.TestCase):
    """Several tools report many distinct issues against one file or URL."""

    def test_distinct_checks_on_one_file_are_kept_apart(self):
        output = (
            '{"results": {"failed_checks": ['
            '{"check_id": "CKV_AWS_1", "check_name": "first", "file_path": "/main.tf"},'
            '{"check_id": "CKV_AWS_2", "check_name": "second", "file_path": "/main.tf"},'
            '{"check_id": "CKV_AWS_3", "check_name": "third", "file_path": "/main.tf"}]}}'
        )
        collected = findings.collect({"steps": [{"tool": "checkov", "stdout": output}]})
        self.assertEqual(collected["counts"]["total"], 3)

    def test_the_same_finding_seen_twice_is_reported_once(self):
        collected = findings.collect({"steps": [
            {"tool": "nmap", "stdout": NMAP},
            {"tool": "nmap", "stdout": NMAP},
        ]})
        self.assertEqual(collected["counts"]["total"], 3)

    def test_one_path_found_by_two_tools_is_kept_as_two_rows(self):
        collected = findings.collect({"steps": [
            {"tool": "ffuf", "stdout": FFUF},
            {"tool": "nikto", "stdout": "+ /admin: Admin page.\n"},
        ]})
        paths = [item["path"] for item in collected["findings"]]
        self.assertEqual(paths.count("/admin"), 2)
        self.assertEqual({item["source"] for item in collected["findings"] if item["path"] == "/admin"},
                         {"ffuf", "nikto"})
