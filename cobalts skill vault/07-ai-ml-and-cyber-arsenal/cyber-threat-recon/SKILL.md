---
name: cyber-threat-recon
description: Algorithmic detection of typosquatting, homoglyphs, deceptive social handles, scam bio patterns, and unified threat scoring.
---

# Cyber Threat Recon & Digital Risk Scoring

Use this skill to detect fake accounts, deceptive brand handles, and calculate threat indices for digital risk protection.

## 1. Typosquatting & Permutation Engine
Scammers alter legitimate handles via:
* **Character Insertion/Omission:** `zomato` -> `zomatto`, `zomto`
* **Substitution/Homoglyphs:** `paytm` -> `paytrn`, `0` for `o`, `1` for `l`
* **Affixes:** `bytexl_support`, `official_bytexl_help`, `swiggy_refund_care`

```python
import Levenshtein

def handle_deception_score(legit_handle: str, suspect_handle: str) -> float:
    legit = legit_handle.lower().strip('@')
    suspect = suspect_handle.lower().strip('@')
    
    # Direct substring with scam affixes
    scam_keywords = ['support', 'care', 'help', 'official', 'refund', 'claims', 'hr']
    contains_affix = any(kw in suspect for kw in scam_keywords)
    
    distance = Levenshtein.distance(legit, suspect)
    ratio = Levenshtein.ratio(legit, suspect)
    
    score = ratio * 50
    if contains_affix and legit in suspect:
        score += 45
    return min(100.0, score)
```

## 2. Unified Risk Calculation Formula
Combine multi-modal signals into a single 0-100 Risk Index:
$$	ext{Risk Score} = 0.40 \cdot S_{	ext{visual}} + 0.35 \cdot S_{	ext{bio}} + 0.25 \cdot S_{	ext{handle}}$$

* **Visual Score ($S_{	ext{visual}}$):** Vector cosine similarity to genuine brand logo.
* **Bio Score ($S_{	ext{bio}}$):** NLP scam/phishing intent probability (crypto, UPI, payment links, DM for prizes).
* **Handle Score ($S_{	ext{handle}}$):** Typosquatting / deceptive similarity index.

## 3. Severity Levels
* **0 - 39%:** LOW (Legitimate fan page or unrelated entity)
* **40 - 69%:** MEDIUM (Suspicious; queue for analyst review)
* **70 - 89%:** HIGH (Likely impersonator; automated warning)
* **90 - 100%:** CRITICAL (Immediate Takedown Notice generated)