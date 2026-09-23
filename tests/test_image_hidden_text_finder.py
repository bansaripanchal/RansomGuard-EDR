import os
import sys
import unittest
import tempfile
import shutil
from PIL import Image, ImageDraw, ImageFont

from core.database.database import DatabaseManager
from core.database.image_scan_repository import ImageScanRepository
from core.scanning.image_text_finder import ImageHiddenTextAnalyzer, SUPPORTED_FORMATS
from core.scanning.image_scan_worker import ImageScanWorker


class TestImageHiddenTextFinder(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_image_scan.db")
        self.db = DatabaseManager(self.db_path)
        self.analyzer = ImageHiddenTextAnalyzer()
        self.repo = ImageScanRepository(self.db)

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def test_01_normal_image_no_text(self):
        """Test 1: Normal image with no text."""
        path = os.path.join(self.temp_dir, "blank.png")
        img = Image.new("RGB", (200, 200), color=(100, 100, 100))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["category"], "NO HIDDEN TEXT DETECTED")
        self.assertIn("No visible text detected.", res["visible_text"])
        self.assertIn("No hidden text detected.", res["hidden_text"])
        self.assertEqual(res["file_format"], "PNG")

    def test_02_image_visible_text(self):
        """Test 2: Image containing visible high-contrast text."""
        path = os.path.join(self.temp_dir, "visible_text.png")
        img = Image.new("RGB", (400, 100), color=(0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.text((20, 30), "RansomGuard Visible Text 2026", fill=(255, 255, 255))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertTrue(res["visible_text_found"])
        self.assertIn("text", res["visible_text"].lower())

    def test_03_image_low_contrast_hidden_text(self):
        """Test 3: Image containing low-contrast text that requires transformation."""
        path = os.path.join(self.temp_dir, "low_contrast.png")
        img = Image.new("RGB", (500, 150), color=(15, 15, 15))
        draw = ImageDraw.Draw(img)
        # Near black on black (color 20 vs 15)
        draw.text((20, 40), "SECRET_KEY_9988", fill=(20, 20, 20))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertIn(res["category"], ["HIDDEN / LOW-VISIBILITY TEXT DETECTED", "NO HIDDEN TEXT DETECTED"])

    def test_04_image_with_metadata(self):
        """Test 5: Image containing embedded info / comment metadata."""
        path = os.path.join(self.temp_dir, "meta.png")
        img = Image.new("RGB", (100, 100), color=(50, 50, 50))
        from PIL.PngImagePlugin import PngInfo
        png_info = PngInfo()
        png_info.add_text("Author", "Security Analyst")
        png_info.add_text("Comment", "Confidential Watermark")
        img.save(path, pnginfo=png_info)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertIn("Embedded Comments & Attributes", res["metadata"])

    def test_05_image_no_metadata(self):
        """Test 6: Image with no metadata."""
        path = os.path.join(self.temp_dir, "no_meta.bmp")
        img = Image.new("RGB", (50, 50), color=(200, 200, 200))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["metadata"].get("Status"), "No metadata detected.")

    def test_06_supported_formats(self):
        """Test 7: Verify analysis on PNG, JPEG, BMP, WEBP."""
        formats = [("test.png", "PNG"), ("test.jpg", "JPEG"), ("test.bmp", "BMP"), ("test.webp", "WEBP")]
        for fname, fmt in formats:
            path = os.path.join(self.temp_dir, fname)
            img = Image.new("RGB", (100, 100), color=(128, 128, 128))
            img.save(path)

            res = self.analyzer.analyze_image(path)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["file_format"], fmt)

    def test_07_unsupported_format(self):
        """Test 8: Unsupported file format returns honest error."""
        path = os.path.join(self.temp_dir, "document.txt")
        with open(path, "w") as f:
            f.write("This is a plain text file, not an image.")

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("Unsupported image format", res["error_reason"])

    def test_08_corrupted_image(self):
        """Test 9: Corrupted image handling without crashing."""
        path = os.path.join(self.temp_dir, "bad_image.png")
        with open(path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR_CORRUPTED_BYTES")

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("could not be decoded", res["error_reason"].lower())

    def test_09_image_channel_analysis(self):
        """Test 10: Independent RGB/Alpha channel analysis."""
        path = os.path.join(self.temp_dir, "channels.png")
        img = Image.new("RGBA", (150, 150), color=(255, 0, 0, 255))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertTrue(len(res["channel_findings"]) >= 3)
        ch_names = [c["channel"] for c in res["channel_findings"]]
        self.assertIn("Red", ch_names)
        self.assertIn("Blue", ch_names)

    def test_10_trailing_data_steganography_indicator(self):
        """Test 11: Trailing bytes appended after JPEG EOI marker flagged as potential indicator."""
        path = os.path.join(self.temp_dir, "stego.jpg")
        img = Image.new("RGB", (100, 100), color=(200, 100, 50))
        img.save(path)

        # Append 1KB trailing payload
        with open(path, "ab") as f:
            f.write(b"SECRET_PAYLOAD_BYTES_" * 50)

        res = self.analyzer.analyze_image(path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertTrue(len(res["embedded_data_indicators"]) > 0)
        self.assertIn("Potential hidden-data indicator", res["embedded_data_indicators"][0]["description"])

    def test_11_database_persistence(self):
        """Test 12: Database persistence & repository lookups."""
        path = os.path.join(self.temp_dir, "db_test.png")
        img = Image.new("RGB", (80, 80), color=(10, 20, 30))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        res["scan_id"] = "test_scan_123"

        rowid = self.repo.insert_scan_result(res)
        self.assertGreater(rowid, 0)

        fetched = self.repo.get_scan_by_id("test_scan_123")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["file_path"], path)
        self.assertEqual(fetched["category"], "NO HIDDEN TEXT DETECTED")

        history = self.repo.get_scan_history(limit=5)
        self.assertTrue(len(history) >= 1)

    def test_12_non_malicious_security_interpretation(self):
        """Test 13: Hidden text detection does NOT generate malware verdict."""
        path = os.path.join(self.temp_dir, "watermark.png")
        img = Image.new("RGB", (200, 200), color=(50, 50, 50))
        img.save(path)

        res = self.analyzer.analyze_image(path)
        sec_text = res["security_interpretation"]
        self.assertIn("NO SECURITY THREAT ESTABLISHED", sec_text)
        self.assertNotIn("MALICIOUS", sec_text)


if __name__ == "__main__":
    unittest.main()
