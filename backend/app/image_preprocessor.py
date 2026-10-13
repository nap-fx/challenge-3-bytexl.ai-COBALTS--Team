"""
Block 2: Image Preprocessing Engine
Aspect-ratio preserving 1:1 padding and 224x224 RGB tensor normalization.
Avoids logo distortion and converts any image into standard neural network inputs.
"""

import io
import urllib.request
from typing import Tuple, Optional
import numpy as np
from PIL import Image

TARGET_SIZE = 224


def pad_to_square(image: Image.Image, background_color: Tuple[int, int, int] = (255, 255, 255)) -> Image.Image:
    """
    Pads a rectangular image into a 1:1 square ratio without stretching or warping.
    Places the logo centered on a clean background.
    """
    image = image.convert("RGB")
    width, height = image.size

    if width == height:
        return image

    max_dim = max(width, height)
    new_img = Image.new("RGB", (max_dim, max_dim), background_color)
    offset_x = (max_dim - width) // 2
    offset_y = (max_dim - height) // 2
    new_img.paste(image, (offset_x, offset_y))
    return new_img


def preprocess_image_to_224_rgb(image: Image.Image) -> Tuple[Image.Image, np.ndarray]:
    """
    1. Pads image to 1:1 square ratio.
    2. Resizes to 224x224 RGB using high-quality Lanczos resampling.
    3. Converts to normalized float32 tensor [1, 3, 224, 224] (standard vision input).
    """
    squared = pad_to_square(image)
    resized = squared.resize((TARGET_SIZE, TARGET_SIZE), Image.Resampling.LANCZOS)

    # Convert to float32 numpy array and normalize [0, 1]
    arr = np.array(resized, dtype=np.float32) / 255.0

    # Standard ImageNet normalization: (x - mean) / std
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    normalized = (arr - mean) / std

    # Transpose to [Channels, Height, Width] -> [3, 224, 224]
    tensor = np.transpose(normalized, (2, 0, 1))
    tensor = np.expand_dims(tensor, axis=0)  # [1, 3, 224, 224]

    return resized, tensor.astype(np.float32)


def fetch_and_preprocess_image(image_source: str) -> Optional[Tuple[Image.Image, np.ndarray]]:
    """
    Fetches image from URL or loads from local file path, then applies 1:1 224x224 RGB pipeline.
    """
    try:
        if image_source.startswith("http://") or image_source.startswith("https://"):
            req = urllib.request.Request(
                image_source,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BrandShieldBot/1.0"}
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = resp.read()
            img = Image.open(io.BytesIO(data))
        else:
            img = Image.open(image_source)
        return preprocess_image_to_224_rgb(img)
    except Exception:
        return None
