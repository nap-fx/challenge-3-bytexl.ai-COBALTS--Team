---
name: pytorch-huggingface-inference
description: Guidelines for loading Hugging Face models (CLIP, DistilBERT, ViT), ONNX runtime export, GPU memory management, and high-throughput inference.
---

# PyTorch & Hugging Face Inference Patterns

Use this skill for running deep learning models efficiently on Google Colab or local inference backends.

## 1. Fast Feature Extraction with Hugging Face CLIP
CLIP embeds both images and text into the exact same vector space:
```python
import torch
from transformers import CLIPProcessor, CLIPModel
from PIL import Image

device = "cuda" if torch.cuda.is_available() else "cpu"
model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(device)
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")

# Disable gradient calculation for inference
@torch.no_grad()
def get_image_embedding(image_path: str):
    image = Image.open(image_path).convert("RGB")
    inputs = processor(images=image, return_tensors="pt").to(device)
    image_features = model.get_image_features(**inputs)
    # L2 normalize
    image_features = image_features / image_features.norm(p=2, dim=-1, keepdim=True)
    return image_features.cpu().numpy().astype("float32")
```

## 2. Text Scam Intent Classification with DistilBERT
```python
from transformers import pipeline

scam_classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    device=0 if torch.cuda.is_available() else -1
)
```

## 3. Memory & Performance Rules
1. Always wrap inference calls in `with torch.no_grad():` or use `@torch.inference_mode()`.
2. Call `torch.cuda.empty_cache()` if handling large batches on Colab.
3. For CPU production servers, export the PyTorch model to **ONNX Runtime** for 3x lower latency.