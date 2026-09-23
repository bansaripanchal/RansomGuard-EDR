import os
import sys
from PIL import Image, ImageDraw, ImageFont, ImageEnhance, ImageOps, ImageFilter

def test_image_analysis():
    # 1. Create a test image with normal visible text AND low-contrast hidden text
    img = Image.new("RGB", (600, 200), color=(15, 15, 15))
    draw = ImageDraw.Draw(img)
    
    # Visible text (high contrast white)
    draw.text((30, 30), "RansomGuard Security Scan", fill=(255, 255, 255))
    
    # Low-visibility / hidden text (near-black fill on dark background: color 18, 18, 18 vs bg 15, 15, 15)
    draw.text((30, 110), "SECRET_KEY_2026", fill=(20, 20, 20))
    
    test_path = "scratch/test_hidden_text.png"
    img.save(test_path)
    print(f"Saved test image to {test_path}")

    # Analyze metadata
    print(f"Format: {img.format}, Size: {img.size}, Mode: {img.mode}")

if __name__ == "__main__":
    test_image_analysis()
