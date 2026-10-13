---
name: faiss-vector-search
description: Meta FAISS vector similarity search, dense vector indexing, cosine distance, sub-vector quantization, and lightning-fast nearest neighbor retrieval.
---

# FAISS Vector Search Best Practices

Use this skill when building similarity search engines for images, text, logos, or digital assets across millions of records in milliseconds.

## 1. Choosing the Right Index
* **IndexFlatIP (Exact Cosine Similarity):** Best for < 100,000 vectors. 100% precision. Must L2-normalize vectors first.
* **IndexIVFFlat (Inverted File Index):** Best for 100K - 5M vectors. Splits space into Voronoi cells. 10x-50x faster.
* **IndexIVFPQ (Product Quantization):** Best for > 5M vectors. Compresses vectors into compact codes. Uses 80% less RAM.

## 2. Standard Cosine Similarity Pipeline (IndexFlatIP)
```python
import faiss
import numpy as np

# 1. Dimension of embeddings (e.g. 512 for CLIP, 384 for MiniLM)
d = 512

# 2. Initialize Inner Product index
index = faiss.IndexFlatIP(d)

# 3. Normalize vectors to unit length so Inner Product == Cosine Similarity
def normalize(vectors: np.ndarray) -> np.ndarray:
    faiss.normalize_L2(vectors)
    return vectors

# 4. Add known brand logos to index
brand_embeddings = np.random.randn(100, d).astype('float32') # replace with real embeddings
normalize(brand_embeddings)
index.add(brand_embeddings)
print(f"Total items indexed: {index.ntotal}")

# 5. Query with suspect image
suspect_vector = np.random.randn(1, d).astype('float32')
normalize(suspect_vector)

k = 5 # top 5 nearest matches
similarities, indices = index.search(suspect_vector, k)

# similarities[0][0] is cosine similarity score (0.0 to 1.0)
top_match_score = float(similarities[0][0])
if top_match_score > 0.90:
    print(f"CRITICAL: Visual Impersonation Match ({top_match_score*100:.1f}%)")
```

## 3. Saving & Loading Indices
```python
# Save to disk
faiss.write_index(index, "brand_assets.index")

# Load from disk (instant startup)
index = faiss.read_index("brand_assets.index")
```