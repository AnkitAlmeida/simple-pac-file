import unittest

from simple_pac_file import PacFile, PacParseError
from simple_pac_file.core import parse_pac


class ParsePacTests(unittest.TestCase):
    def test_extracts_function_and_dns_helpers(self):
        text = (
            "function FindProxyForURL(url, host) {\n"
            "  if (dnsDomainIs(host, '.internal')) {\n"
            "    return 'DIRECT';\n"
            "  }\n"
            "  if (isInNet(host, '10.0.0.0', '255.0.0.0')) {\n"
            "    return dnsResolve(host) ? 'PROXY proxy:8080' : 'DIRECT';\n"
            "  }\n"
            "  return 'PROXY upstream:3128';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertIsInstance(pac, PacFile)
        self.assertTrue(pac.find_proxy_for_url.startswith("function FindProxyForURL"))
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))
        self.assertEqual(pac.dns_helpers, ["dnsDomainIs", "dnsResolve", "isInNet"])
        self.assertEqual(pac.source, text)

    def test_preserves_exact_source_slice(self):
        text = "function FindProxyForURL(u,h){return 'DIRECT';}\n"
        pac = parse_pac(text)
        # The extracted text must be the exact characters from function to }.
        self.assertEqual(pac.find_proxy_for_url, "function FindProxyForURL(u,h){return 'DIRECT';}")

    def test_missing_function_raises(self):
        with self.assertRaises(PacParseError):
            parse_pac("function helper() { return 1; }\n")

    def test_non_str_raises_typeerror(self):
        with self.assertRaises(TypeError):
            parse_pac(123)  # type: ignore[arg-type]

    def test_string_containing_brace_does_not_confuse_depth(self):
        # A brace inside a string literal must not close the function early.
        text = "function FindProxyForURL(u,h){return '{';}\n"
        pac = parse_pac(text)
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))
        self.assertIn("{';}", pac.find_proxy_for_url)

    def test_line_comment_braces_ignored(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  // { should not close the function\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))

    def test_block_comment_braces_ignored(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  /* { do not close } */\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))

    def test_nested_function_ignored_for_top_level_lookup(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  function inner(){ return 1; }\n"
            "  return inner();\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))
        # The inner function text is part of the outer function body, so it is included.
        self.assertIn("function inner()", pac.find_proxy_for_url)

    def test_helper_inside_string_not_detected(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  var s = 'dnsResolve is great';\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertEqual(pac.dns_helpers, [])

    def test_dotted_member_access_not_detected(self):
        # foo.dnsResolve( should not count as the dnsResolve helper.
        text = (
            "function FindProxyForURL(u,h){\n"
            "  var x = foo.dnsResolve(h);\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertEqual(pac.dns_helpers, [])

    def test_whitespace_between_name_and_paren_still_detected(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  return dnsResolve (h) ? 'DIRECT' : 'PROXY p:8080';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertEqual(pac.dns_helpers, ["dnsResolve"])

    def test_escape_sequences_in_strings_do_not_break_scan(self):
        text = (
            "function FindProxyForURL(u,h){\n"
            "  var s = 'it\\'s ok';\n"
            "  var t = \"he said \\\"hi\\\"\";\n"
            "  if (isResolvable(h)) { return 'DIRECT'; }\n"
            "  return 'PROXY p:8080';\n"
            "}\n"
        )
        pac = parse_pac(text)
        self.assertEqual(pac.dns_helpers, ["isResolvable"])
        self.assertTrue(pac.find_proxy_for_url.rstrip().endswith("}"))

    def test_empty_text_raises(self):
        with self.assertRaises(PacParseError):
            parse_pac("")


if __name__ == "__main__":
    unittest.main()
