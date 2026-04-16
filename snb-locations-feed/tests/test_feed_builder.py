import unittest

from feed_builder import normalize_address, normalize_phone, strip_html


class FeedBuilderTests(unittest.TestCase):
    def test_strip_html_removes_tags_and_keeps_line_breaks(self) -> None:
        raw = "<br><strong>Режим работы:</strong> с 9:00 до 18:00<br>без перерыва"
        self.assertEqual(strip_html(raw), "Режим работы: с 9:00 до 18:00\nбез перерыва")

    def test_normalize_address_cleans_whitespace(self) -> None:
        raw = " ул. Колхозная, д.20, магазин «Магнит»<br>\n"
        self.assertEqual(normalize_address(raw), "ул. Колхозная, д.20, магазин «Магнит»")

    def test_normalize_phone_flattens_multiline_value(self) -> None:
        raw = "<br>(8212) 40-97-26<br>(8212) 40-97-10"
        self.assertEqual(normalize_phone(raw), "(8212) 40-97-26 (8212) 40-97-10")


if __name__ == "__main__":
    unittest.main()
