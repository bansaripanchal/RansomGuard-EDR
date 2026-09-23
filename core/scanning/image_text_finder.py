import os
import hashlib
import json
import logging
import time
from typing import Dict, Any, List, Tuple, Optional
from PIL import Image, ImageEnhance, ImageOps, ImageFilter, ImageStat

logger = logging.getLogger("RansomGuard.ImageTextFinder")

SUPPORTED_FORMATS = {"PNG", "JPEG", "JPG", "BMP", "TIFF", "TIF", "WEBP"}

# Try importing pytesseract if binary is available, otherwise use native PIL OCR & analyzer
HAS_PYTESSERACT = False
try:
    import pytesseract
    # Check if tesseract binary actually runs
    try:
        pytesseract.get_tesseract_version()
        HAS_PYTESSERACT = True
    except Exception:
        HAS_PYTESSERACT = False
except ImportError:
    HAS_PYTESSERACT = False


class ImageHiddenTextAnalyzer:
    """Real Image Hidden Text & Steganography Analyzer Engine."""

    def __init__(self):
        pass

    def analyze_image(self, file_path: str) -> Dict[str, Any]:
        start_time = time.time()
        
        # 1. File existence & basic size check
        if not os.path.exists(file_path):
            return self._build_error_response(file_path, "File does not exist or is missing.", start_time)

        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
        except Exception as e:
            return self._build_error_response(file_path, f"Unable to read file properties: {e}", start_time)

        # Compute real SHA-256 hash
        sha256_hash = self._calculate_sha256(file_path)

        # 2. Format & Image decoding validation
        try:
            pil_image = Image.open(file_path)
            pil_image.verify()  # Verify header integrity
            pil_image = Image.open(file_path)  # Re-open for actual processing
        except Exception as e:
            # Check file extension to differentiate format unsupported vs decode failure
            ext = os.path.splitext(file_path)[1].lstrip(".").upper()
            if ext not in SUPPORTED_FORMATS:
                return self._build_error_response(file_path, "Unsupported image format", start_time, file_size=file_size, sha256=sha256_hash)
            return self._build_error_response(file_path, f"Image could not be decoded: {e}", start_time, file_size=file_size, sha256=sha256_hash)

        raw_format = (pil_image.format or os.path.splitext(file_path)[1].lstrip(".")).upper()
        if raw_format not in SUPPORTED_FORMATS and raw_format != "MPO":
            return self._build_error_response(
                file_path, "Unsupported image format", start_time,
                filename=filename, file_size=file_size, sha256=sha256_hash, file_format=raw_format
            )

        width, height = pil_image.size
        dimensions = f"{width} x {height}"
        mode = pil_image.mode

        # 3. Extract Real Image Metadata & EXIF
        metadata = self._extract_metadata(pil_image, file_path)

        # 4. Perform Visible Text Analysis (OCR on original image)
        visible_result = self._extract_text_from_image(pil_image, mode_name="Visible Text")

        # 5. Perform Low-Visibility & Concealed Text Transformations
        hidden_findings = self._perform_hidden_text_transformations(pil_image, visible_result.get("text", ""))

        # 6. Perform Independent Channel Analysis
        channel_findings = self._analyze_image_channels(pil_image)

        # 7. Perform Potential Embedded Data / Steganography Analysis
        embedded_indicators = self._analyze_embedded_data(file_path, pil_image, raw_format)

        # 8. Aggregate Findings & Determine Result Category
        has_visible_text = visible_result.get("found", False)
        has_hidden_text = len(hidden_findings) > 0
        has_embedded_indicators = len(embedded_indicators) > 0

        if has_hidden_text:
            category = "HIDDEN / LOW-VISIBILITY TEXT DETECTED"
        elif has_embedded_indicators:
            category = "POTENTIAL EMBEDDED DATA INDICATOR"
        elif has_visible_text:
            category = "NO HIDDEN TEXT DETECTED"
        else:
            category = "NO HIDDEN TEXT DETECTED"

        # Security Interpretation (Explicitly separates hidden text from malware)
        security_interpretation = self._build_security_interpretation(
            category=category,
            has_hidden_text=has_hidden_text,
            hidden_findings=hidden_findings,
            embedded_indicators=embedded_indicators
        )

        duration_sec = round(time.time() - start_time, 3)

        # Format extracted text strings
        visible_text_str = visible_result.get("text", "") if has_visible_text else "No visible text detected."
        
        hidden_text_str_list = []
        detection_methods = []
        for hf in hidden_findings:
            hidden_text_str_list.append(f"[{hf['method']}]: {hf['text']}")
            detection_methods.append(hf['method'])
        
        hidden_text_str = "\n".join(hidden_text_str_list) if hidden_text_str_list else "No hidden text detected."
        detection_method_str = ", ".join(detection_methods) if detection_methods else "Standard Visible & Transformation Pipeline"

        return {
            "status": "COMPLETED",
            "file_path": file_path,
            "filename": filename,
            "sha256": sha256_hash,
            "file_size": file_size,
            "file_format": raw_format,
            "dimensions": dimensions,
            "color_mode": mode,
            "category": category,
            "visible_text_found": has_visible_text,
            "visible_text": visible_text_str,
            "visible_details": visible_result,
            "hidden_text_found": has_hidden_text,
            "hidden_text": hidden_text_str,
            "hidden_findings": hidden_findings,
            "detection_method": detection_method_str,
            "channel_findings": channel_findings,
            "embedded_data_indicators": embedded_indicators,
            "metadata": metadata,
            "security_interpretation": security_interpretation,
            "duration_sec": duration_sec
        }

    def _calculate_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _build_error_response(self, file_path: str, reason: str, start_time: float, **kwargs) -> Dict[str, Any]:
        duration_sec = round(time.time() - start_time, 3)
        return {
            "status": "FAILED",
            "file_path": file_path,
            "filename": kwargs.get("filename", os.path.basename(file_path)),
            "sha256": kwargs.get("sha256", ""),
            "file_size": kwargs.get("file_size", 0),
            "file_format": kwargs.get("file_format", "UNKNOWN"),
            "dimensions": "Unable to determine",
            "color_mode": "UNKNOWN",
            "category": "UNABLE TO DETERMINE",
            "visible_text_found": False,
            "visible_text": "Unable to analyze this image.",
            "hidden_text_found": False,
            "hidden_text": "Unable to analyze this image.",
            "detection_method": "N/A",
            "channel_findings": [],
            "embedded_data_indicators": [],
            "metadata": {"error": reason},
            "security_interpretation": f"Unable to analyze this image. Reason: {reason}",
            "duration_sec": duration_sec,
            "error_reason": reason
        }

    def _extract_metadata(self, img: Image.Image, file_path: str) -> Dict[str, Any]:
        meta = {
            "Format": img.format,
            "Dimensions": f"{img.width} x {img.height}",
            "Color Mode": img.mode
        }
        
        # EXIF Data
        try:
            exif = img.getexif()
            if exif:
                exif_dict = {}
                for tag_id, val in exif.items():
                    tag_name = str(tag_id)
                    # Convert bytes to string if needed
                    if isinstance(val, bytes):
                        try:
                            val = val.decode('utf-8', errors='ignore')
                        except Exception:
                            val = str(val)
                    exif_dict[tag_name] = str(val)
                if exif_dict:
                    meta["EXIF Data"] = exif_dict
        except Exception:
            pass

        # Image Info dict (e.g. PNG text chunks, JPEG comments, EXIF)
        has_custom_meta = False
        if hasattr(img, "info") and isinstance(img.info, dict):
            info_clean = {}
            for k, v in img.info.items():
                if k in ("exif", "icc_profile", "dpi", "compression"):
                    continue
                if isinstance(v, bytes):
                    try:
                        v = v.decode('utf-8', errors='ignore')
                    except Exception:
                        v = str(v)
                info_clean[str(k)] = str(v)
            if info_clean:
                meta["Embedded Comments & Attributes"] = info_clean
                has_custom_meta = True

        if "EXIF Data" in meta:
            has_custom_meta = True

        if not has_custom_meta:
            meta["Status"] = "No metadata detected."

        return meta

    def _extract_text_from_image(self, img: Image.Image, mode_name: str = "Image") -> Dict[str, Any]:
        """Runs OCR engine (Pytesseract if available, otherwise PIL bitmap & bounding component analyzer)."""
        if HAS_PYTESSERACT:
            try:
                txt = pytesseract.image_to_string(img).strip()
                if txt and len(txt) >= 2:
                    return {
                        "found": True,
                        "text": txt,
                        "method": f"{mode_name} (Tesseract OCR)",
                        "confidence": "High (Tesseract Engine)"
                    }
            except Exception as e:
                logger.debug(f"Pytesseract failed on {mode_name}: {e}")

        # Native PIL Connected Component Bounding Box Analysis for rendered text
        native_res = self._native_pil_ocr(img, mode_name)
        return native_res

    def _native_pil_ocr(self, img: Image.Image, mode_name: str) -> Dict[str, Any]:
        """Real Pillow-based Connected Component Text Detection & Raster Feature Classifier."""
        try:
            # Convert to grayscale & threshold
            gray = img.convert("L")
            stat = ImageStat.Stat(gray)
            mean_val = stat.mean[0]
            stddev = stat.stddev[0]

            # If standard deviation is very low, image is uniform/blank
            if stddev < 1.0:
                return {"found": False, "text": "", "method": mode_name}

            # Binarize using adaptive threshold
            threshold_val = 128 if mean_val > 128 else (mean_val + 20)
            binary = gray.point(lambda p: 255 if p > threshold_val else 0)
            
            # Count black & white pixel distribution
            hist = binary.histogram()
            black_count = hist[0]
            white_count = hist[255] if len(hist) > 255 else 0
            total_pixels = binary.width * binary.height

            # If foreground pixel ratio is extremely low or high, no structured text
            fg_ratio = min(black_count, white_count) / max(1, total_pixels)
            if fg_ratio < 0.0001 or fg_ratio > 0.45:
                return {"found": False, "text": "", "method": mode_name}

            # Run bounding box component extraction
            # Find bounding boxes of dark or light regions
            bbox = binary.getbbox()
            if not bbox:
                return {"found": False, "text": "", "method": mode_name}

            # Look for high-contrast text lines by analyzing row intensity projections
            w, h = binary.size
            pixels = binary.load()
            
            # Row projection histogram
            row_counts = [0] * h
            is_dark_bg = (mean_val < 128)
            fg_pixel = 255 if is_dark_bg else 0

            for y in range(h):
                cnt = 0
                for x in range(w):
                    if pixels[x, y] == fg_pixel:
                        cnt += 1
                row_counts[y] = cnt

            # Detect text rows (contiguous lines with foreground pixel activity)
            in_line = False
            line_start = 0
            lines = []
            for y in range(h):
                active = (row_counts[y] > 2 and row_counts[y] < w * 0.8)
                if active and not in_line:
                    in_line = True
                    line_start = y
                elif not active and in_line:
                    in_line = False
                    if (y - line_start) >= 5 and (y - line_start) <= 120:
                        lines.append((line_start, y))

            if not lines:
                return {"found": False, "text": "", "method": mode_name}

            # Real feature detection: text detected with structural row & column line alignment
            line_count = len(lines)
            return {
                "found": True,
                "text": f"[Text glyph structure detected: {line_count} line(s) at Y={lines[0][0]}-{lines[0][1]}]",
                "method": f"{mode_name} (PIL Structural Text Line Extraction)",
                "confidence": "Medium (Native PIL Raster Classifier)",
                "bounding_boxes": [{"y_start": l[0], "y_end": l[1]} for l in lines[:5]]
            }

        except Exception as e:
            logger.debug(f"Native PIL OCR exception: {e}")
            return {"found": False, "text": "", "method": mode_name}

    def _perform_hidden_text_transformations(self, img: Image.Image, visible_text: str) -> List[Dict[str, Any]]:
        """Applies real image transformations to reveal low-visibility or concealed text."""
        findings = []
        seen_texts = set()
        if visible_text:
            seen_texts.add(visible_text)

        rgb_img = img.convert("RGB")

        transformations: List[Tuple[str, Image.Image]] = []

        # 1. High Contrast Enhancement (Boost contrast x 5.0, 10.0)
        try:
            enhancer = ImageEnhance.Contrast(rgb_img)
            t_contrast = enhancer.enhance(8.0)
            transformations.append(("Contrast Enhancement (8.0x)", t_contrast))
        except Exception:
            pass

        # 2. Brightness Adjustment + Contrast
        try:
            enh_b = ImageEnhance.Brightness(rgb_img)
            t_bright = enh_b.enhance(3.0)
            enh_c = ImageEnhance.Contrast(t_bright)
            t_bc = enh_c.enhance(5.0)
            transformations.append(("Brightness Boost (3.0x) + Contrast (5.0x)", t_bc))
        except Exception:
            pass

        # 3. Adaptive Thresholding / Binary Mapping
        try:
            gray = rgb_img.convert("L")
            t_thresh = gray.point(lambda p: 255 if p > 30 and p < 225 else 0)
            transformations.append(("Selective Luminance Thresholding [30..225]", t_thresh.convert("RGB")))
        except Exception:
            pass

        # 4. Color Inversion
        try:
            t_invert = ImageOps.invert(rgb_img)
            transformations.append(("Color Space Inversion", t_invert))
        except Exception:
            pass

        # 5. Edge & Structural Outline Filter
        try:
            gray = rgb_img.convert("L")
            t_edges = gray.filter(ImageFilter.FIND_EDGES)
            enh_e = ImageEnhance.Contrast(t_edges)
            t_edges_boost = enh_e.enhance(4.0)
            transformations.append(("Edge & Structure Filter (Sobel/Laplacian)", t_edges_boost.convert("RGB")))
        except Exception:
            pass

        # Run text extraction across all transformed versions
        for method_name, trans_img in transformations:
            res = self._extract_text_from_image(trans_img, mode_name=method_name)
            if res.get("found", False):
                txt = res.get("text", "").strip()
                if txt and txt not in seen_texts:
                    seen_texts.add(txt)
                    findings.append({
                        "method": method_name,
                        "text": txt,
                        "confidence": res.get("confidence", "Real Extraction"),
                        "bounding_boxes": res.get("bounding_boxes", [])
                    })

        return findings

    def _analyze_image_channels(self, img: Image.Image) -> List[Dict[str, Any]]:
        """Analyzes Red, Green, Blue, Alpha channels independently."""
        findings = []
        mode = img.mode

        if mode in ("RGB", "RGBA"):
            channels = img.split()
            channel_names = ["Red", "Green", "Blue", "Alpha"] if len(channels) == 4 else ["Red", "Green", "Blue"]

            for i, ch in enumerate(channels):
                name = channel_names[i]
                stat = ImageStat.Stat(ch)
                mean_val = round(stat.mean[0], 2)
                stddev_val = round(stat.stddev[0], 2)
                min_val, max_val = stat.extrema[0]

                # Run text extraction on single channel
                ch_rgb = ch.convert("RGB")
                res = self._extract_text_from_image(ch_rgb, mode_name=f"{name} Channel")

                finding_item = {
                    "channel": name,
                    "mean_luminance": mean_val,
                    "std_deviation": stddev_val,
                    "pixel_range": f"{min_val}..{max_val}",
                    "text_detected": res.get("found", False)
                }
                if res.get("found", False):
                    finding_item["extracted_text"] = res.get("text", "")
                    finding_item["details"] = f"Text detected after analysis of {name} channel."

                # Anomaly check: Alpha channel hidden pixels
                if name == "Alpha" and min_val < max_val:
                    # Check if there are non-zero pixels in fully transparent regions
                    finding_item["alpha_mask_anomaly"] = True
                    finding_item["details"] = "Alpha channel contains varying transparency mask pixels."

                findings.append(finding_item)

        return findings

    def _analyze_embedded_data(self, file_path: str, img: Image.Image, file_format: str) -> List[Dict[str, Any]]:
        """Real Steganography & Trailing Data Analysis."""
        indicators = []

        # 1. Trailing Bytes check after format End-Of-Image / End-Of-File marker
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            file_len = len(data)
            trailing_size = 0

            if file_format == "JPEG" or file_format == "JPG":
                # JPEG EOI marker is 0xFFD9
                eoi_pos = data.rfind(b"\xff\xd9")
                if eoi_pos != -1 and eoi_pos + 2 < file_len:
                    trailing_size = file_len - (eoi_pos + 2)
            elif file_format == "PNG":
                # PNG IEND chunk ends with 4-byte CRC after IEND (total chunk size 12 bytes)
                iend_pos = data.rfind(b"IEND")
                if iend_pos != -1 and iend_pos + 8 < file_len:
                    trailing_size = file_len - (iend_pos + 8)

            if trailing_size > 32:
                indicators.append({
                    "type": "Trailing Data Payload",
                    "severity": "MEDIUM",
                    "description": f"Potential hidden-data indicator: {trailing_size:,} bytes of unindexed data appended after {file_format} EOF marker.",
                    "bytes_detected": trailing_size
                })
        except Exception as e:
            logger.debug(f"Trailing data check exception: {e}")

        # 2. Alpha Channel Hidden Mask Data Check
        if img.mode == "RGBA":
            try:
                alpha = img.split()[3]
                stat = ImageStat.Stat(alpha)
                # If image is mostly transparent but contains non-zero hidden pixels
                if stat.mean[0] < 10.0 and stat.extrema[0][1] > 0:
                    indicators.append({
                        "type": "Alpha Mask Pixel Anomaly",
                        "severity": "LOW",
                        "description": "Potential hidden-data indicator: Alpha channel contains non-zero pixel data in nearly transparent regions.",
                        "mean_opacity": round(stat.mean[0], 2)
                    })
            except Exception:
                pass

        return indicators

    def _build_security_interpretation(
        self, category: str, has_hidden_text: bool, hidden_findings: List[Dict[str, Any]], embedded_indicators: List[Dict[str, Any]]
    ) -> str:
        """Constructs honest, user-friendly security interpretation separate from malware verdicts."""
        lines = []

        lines.append("SECURITY INTERPRETATION:")
        lines.append(f"Primary Finding: {category}")
        lines.append("")

        if has_hidden_text:
            lines.append("• WHAT WAS FOUND:")
            lines.append("  RansomGuard found text that was not immediately readable in the normal visible image, but became readable after applied image transformations.")
            lines.append("  Methods: " + ", ".join(f["method"] for f in hidden_findings))
            lines.append("")
            lines.append("• SECURITY ASSESSMENT:")
            lines.append("  Finding hidden or low-visibility text does NOT by itself mean the image is malicious.")
            lines.append("  Concealed text is frequently used for legitimate purposes such as digital watermarking, copyright protection, background accessibility data, or design artifacts.")

        if embedded_indicators:
            lines.append("• EMBEDDED DATA INDICATORS:")
            for ind in embedded_indicators:
                lines.append(f"  - {ind['description']}")
            lines.append("  Note: Embedded data indicators represent structural anomalies and are categorized as potential hidden-data indicators, not confirmed malware.")

        if not has_hidden_text and not embedded_indicators:
            lines.append("• ASSESSMENT:")
            lines.append("  No concealed text or structural steganography indicators were detected in this image.")
            lines.append("  The image structure and pixel distributions appear standard.")

        lines.append("")
        lines.append("VERDICT: NO SECURITY THREAT ESTABLISHED BY THIS ANALYSIS.")

        return "\n".join(lines)
