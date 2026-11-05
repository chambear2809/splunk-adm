import unittest

from tools.demo_links import GUIDE, render


class DemoLinksTest(unittest.TestCase):
    def test_guide_publishes_no_stack_name(self):
        text = GUIDE.read_text()
        self.assertIn("https://<stack>.splunkcloud.com/", text)
        self.assertNotRegex(text, r"https://(?!<stack>)[a-z0-9-]+\.splunkcloud\.com")

    def test_render_fills_stack_and_rejects_unsafe_names(self):
        self.assertEqual(
            render("https://<stack>.splunkcloud.com/x", "acme-prod"),
            "https://acme-prod.splunkcloud.com/x",
        )
        for bad in ("", "evil.com/", "a b", "../x", "x" * 70):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                render("<stack>", bad)


if __name__ == "__main__":
    unittest.main()
