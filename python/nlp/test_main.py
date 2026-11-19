import unittest

from nlp.__main__ import extract


class EntityExtractionTests(unittest.TestCase):
    def test_extracts_extended_entities(self):
        text = """Contact Jane Doe at jane@example.com or +1 415 555 0199.
        Acme Technologies is a subsidiary of Globex Corp.
        Headquarters: 1600 Amphitheatre Parkway, Mountain View.
        Project Nightfall was discussed; codename "BlueHeron"."""
        result = extract(text)
        self.assertIn("jane@example.com", result["emails"])
        self.assertTrue(result["people"])
        self.assertIn("Acme Technologies", result["organizations"])
        self.assertTrue(result["physical_addresses"])
        self.assertIn("Nightfall", result["project_names"])
        self.assertIn("BlueHeron", result["codenames"])


if __name__ == "__main__":
    unittest.main()
