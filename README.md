# 🛡️ AegisMark AI: Master Blueprint & Execution Outline
## Challenge 03: Digital Risk Protection Platform (Presented by Kampus.vc | HacXLerate 2026)

> **Team Lead:** Abdul Malik | **Institution:** Chandigarh University  
> **Target Track:** Challenge 03 — Digital Risk Protection (Brand Impersonation, Scam Accounts & Rogue Apps)  
> **Target Audience:** VC Judges (Kampus.vc), Technical Mentors (ByteXL), and Enterprise Security Leads  

---

## 1. Executive Summary & Problem Statement

### The Real-World Crisis
Fast-growing startups, fintechs, and tech institutions (like ByteXL, Zomato, Zerodha, and universities) face a massive wave of **digital impersonation**:
* **Fake Social Accounts:** Fraudsters create handles like `@bytexl_support_official` or `@zomato_refunds` on Instagram, X, and Telegram to steal user payments and credentials.
* **Deceptive App Clones:** Malicious APKs distributed on third-party stores mimicking genuine apps to install spyware.
* **Typosquatting & Homoglyphs:** Attackers swap letters (`paytm` ➔ `paytrn`, `0` for `o`) to bypass naive regex filters.

### Why Existing Solutions Fail
1. **Manual Reporting is Too Slow:** Brands only discover scam accounts after victims complain (average detection time: 72+ hours).
2. **Naive Keyword Filtering Fails:** Basic regex cannot detect altered logos, homoglyphic characters, or nuanced scam intent in bios.
3. **Chatbot Wrappers Lack Depth:** Most hackathon teams present a shallow ChatGPT wrapper that cannot scale or process images in real time.

### Our Solution: **AegisMark AI**
An autonomous, multi-modal **Digital Risk Protection (DRP) Platform** that continuously scans social handles, calculates a unified 0–100 Threat Index using **vector similarity (FAISS) and NLP**, and generates automated **1-Click Legal Takedown Notices**.

---

## 2. The 3-Pillar Multi-Modal Detection Engine

```
                       ┌──────────────────────────────────────┐
                       │  INPUT: Suspect Handle / URL / App   │
                       └──────────────────┬───────────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
      ┌───────────────────────┐ ┌───────────────────┐ ┌───────────────────────┐
      │   PILLAR 1: VISION    │ │  PILLAR 2: NLP    │ │  PILLAR 3: HEURISTIC  │
      │   FAISS + CLIP/ViT    │ │  Intent & Bio     │ │  Typosquatting Engine │
      │  Dense Vector Search  │ │  Entity Extractor │ │  Homoglyphs & Leven.  │
      └───────────┬───────────┘ └─────────┬─────────┘ └───────────┬───────────┘
                  │                       │                       │
                  └───────────────────────┼───────────────────────┘
                                          ▼
                      ┌───────────────────────────────────────┐
                      │      UNIFIED RISK SCORING ENGINE      │
                      │  Risk = 0.40(Vis) + 0.35(Bio) + 0.25  │
                      └──────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │    ACTION: 1-Click Legal Takedown     │
                      │      & Forensic PDF Report            │
                      └───────────────────────────────────────┘
```

### Pillar 1: Visual Asset & Logo Matching (Vision)
* **Technology:** Meta **FAISS (Facebook AI Similarity Search)** + **OpenAI CLIP / MobileNetV2**.
* **Mechanism:** 
  * The legitimate brand's logo and official brand assets are converted into 512-dimensional dense neural embeddings and stored in a high-speed FAISS `IndexFlatIP` index.
  * When a suspect profile avatar or app icon is scanned, its embedding is computed and compared against the index in **under 15 milliseconds**.
  * Detects cropped logos, altered background colors, watermarked badges, and modified aspect ratios with >90% precision.

### Pillar 2: Scam Intent & Bio Analysis (NLP)
* **Technology:** Lightweight Transformer (**DistilBERT / RoBERTa**) + Pattern Heuristics.
* **Mechanism:**
  * Analyzes the bio and recent post text for high-risk fraud signatures:
    * Payment solicitation: *"Send ₹500 registration fee"*, UPI IDs (`@okhdfcbank`, `@paytm`).
    * Urgency & Impersonation cues: *"Official customer desk"*, *"Immediate refund"*, *"Telegram support channel"*.
    * External phishing URLs (shortened Bitly, tinyurl, raw IP links).

### Pillar 3: Typosquatting & Metadata Heuristics
* **Technology:** Algorithmic String Matching (**Levenshtein Distance**, Homoglyphs, Affix Matcher).
* **Mechanism:**
  * Calculates deception distance between genuine brand handle and suspect handle:
    * Character insertion/omission: `bytexl` ➔ `byte_xll`
    * Homoglyph substitution: `l` replaced with `1`, `o` with `0`, `rn` for `m`.
    * Scam affixes: `_support`, `_helpdesk`, `_care`, `_official_india`.
  * Checks metadata anomalies (e.g., account created 3 days ago, 12 followers, following 8,000 accounts).

---

## 3. The Unified Threat Scoring Formula (0 - 100)

Every scanned asset receives an objective, mathematically grounded **Threat Index**:

$$\text{Threat Score} = \left(0.40 \times S_{\text{visual}}\right) + \left(0.35 \times S_{\text{bio}}\right) + \left(0.25 \times S_{\text{handle}}\right)$$

Where:
* $S_{\text{visual}}$: Normalized Cosine Similarity from FAISS ($0 - 100\%$)
* $S_{\text{bio}}$: NLP Scam Intent Probability ($0 - 100\%$)
* $S_{\text{handle}}$: Typosquatting / Deception Ratio ($0 - 100\%$)

### Severity Classification & Action Tiers:
| Threat Score | Threat Level | Color Code | Automated Action |
| :---: | :---: | :---: | :--- |
| **0 – 39%** | **LOW / SAFE** | Emerald Green (`#10b981`) | Verified partner, fan page, or unrelated entity. Logged only. |
| **40 – 69%** | **MEDIUM** | Cyber Yellow (`#eab308`) | Suspicious activity; queued for human security analyst review. |
| **70 – 89%** | **HIGH** | Neon Amber (`#f97316`) | Probable impersonator; automated warning issued to brand admins. |
| **90 – 100%**| **CRITICAL** | Crimson Red (`#ef4444`) | **Confirmed Impersonation Attack; Instant Takedown Package Generated.** |

---

## 4. The Killer Feature: 1-Click Automated Legal Takedown

Judges at VC hackathons want to see **immediate business resolution**, not just diagnosis:
* When a **CRITICAL** threat is detected, the dashboard activates the **"Generate Legal Takedown"** button.
* In 1 click, AegisMark AI generates a formal **Cease & Desist / DMCA Infringement Package**:
  1. **Forensic Evidence:** Timestamped suspect URL, handle ID, and side-by-side visual proof with similarity percentage.
  2. **Legal Citation:** Trademark infringement clauses under the Information Technology Act & platform terms of service.
  3. **Direct Action:** Pre-addressed email templates for Meta / X / Telegram abuse desks, ready for one-click transmission.

---

## 5. Technology Stack & Implementation Architecture

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Frontend Dashboard** | **Next.js 15 / React 19 + Tailwind CSS v4** | Ultra-responsive, production-grade cybersecurity dark mode. |
| **UI Components** | **shadcn/ui + Lucide Icons + Framer Motion** | Silicon Valley aesthetic, pulsing threat radar, smooth drawer modals. |
| **Backend REST API** | **Python 3.11 + FastAPI (Async)** | Blazing fast async performance, Pydantic v2 schemas, zero-block inference. |
| **Vector Search Engine**| **Meta FAISS (`faiss-cpu`)** | Sub-second visual vector similarity search across thousands of assets. |
| **Neural Embeddings** | **OpenAI CLIP (ViT-B/32) via Hugging Face** | Unified vision-language embeddings for zero-shot logo matching. |
| **Development Tool** | **Google Antigravity (AGY) IDE + Google Colab** | Rapid agentic vibe coding, model prototyping, and live serving. |

---

## 6. The 4 Core Dashboard Screens (The Demo Flow)

1. **Screen 1: Security Operations Center (SOC) Command Hub**
   * Top KPI Strip: Active Monitored Brands (`14`), Total Scanned Accounts (`8,450`), Critical Impersonators Intercepted (`6`).
   * Live Threat Radar: Animated circular radar pinging active threats across Instagram, X, and Telegram.
2. **Screen 2: Real-Time Deep Scanner**
   * Input bar: Brand Name (e.g., `ByteXL`) + Target Suspect Handle (e.g., `@bytexl_careers_official`).
   * "Run AI Threat Scan" button: Triggers real-time multi-modal analysis with live loading telemetry.
3. **Screen 3: Split Forensic Comparison View (Original vs. Imposter)**
   * **Left Side (Legitimate):** Verified blue badge, official logo, official support link.
   * **Right Side (Imposter):** Cropped logo with bounding box, highlighted red scam text (*"Pay ₹350 for interview"*), typosquatted handle.
   * **Center Radial Gauge:** Animated SVG gauge displaying **96% CRITICAL THREAT**.
4. **Screen 4: Automated Enforcement & Takedown Drawer**
   * Pre-rendered legal Cease & Desist document.
   * One-click "Export PDF Notice" and "Copy Abuse Desk Email".

---

## 7. Team Task Division & Sprint Roadmap (24–48 Hours)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SPRINT MILESTONE TIMELINE                       │
├────────────────────┬───────────────────────────────────────────────────┤
│ PHASE 1 (Hours 0-6)│ Repo setup, Mock Dataset creation, FAISS pipeline │
├────────────────────┼───────────────────────────────────────────────────┤
│ PHASE 2 (Hrs 6-18) │ FastAPI backend endpoints + AGY Frontend build    │
├────────────────────┼───────────────────────────────────────────────────┤
│ PHASE 3 (Hrs 18-30)│ Model integration, End-to-end testing, UI polish  │
├────────────────────┼───────────────────────────────────────────────────┤
│ PHASE 4 (Hrs 30-36)│ Demo rehearsal, Slide deck, 3-minute pitch timing │
└────────────────────┴───────────────────────────────────────────────────┘
```

### Role 1: Team Lead & Integrator (Abdul Malik)
* Project vision, system architecture, and API integration between frontend and backend.
* Final pitch presentation, slides, and live demo choreography.

### Role 2: AI/ML & Backend Specialist
* Implement FAISS vector index and CLIP embedding extraction in Python/Colab.
* Build the FastAPI `/api/v1/scan` and `/api/v1/takedown` endpoints using Pydantic v2.

### Role 3: Frontend & UI/UX Specialist
* Build the dark-mode SOC dashboard in AGY IDE using `shadcn`, `tailwind-4`, and `framer-motion`.
* Implement the interactive threat radar, circular score gauges, and forensic comparison split view.

---

## 8. The Winning 3-Minute Hackathon Pitch Script

* **[0:00 – 0:45] The Hook (The Real Problem):**  
  *"Judges, right now, while we are presenting in this room, a student looking for a ByteXL job or a Zomato refund is being scammed by a fake Telegram channel or Instagram handle. Brands spend millions building trust, but scammers steal it in seconds with fake logos and deceptive usernames. Current brand protection takes 72 hours of manual complaints. We built **AegisMark AI** to solve this in under 2 seconds."*
* **[0:45 – 1:45] The Live Demonstration (The 'Aha!' Moment):**  
  *(Open the AGY live dashboard in dark mode)*  
  *"Here is our live platform. Let's enter ByteXL and scan a suspect account `@bytexl_support_official`. Watch what happens when we hit Scan..."*  
  *(Radar pulses, results pop up)*  
  *"In 120 milliseconds, our multi-modal engine did three things: First, Meta FAISS matched their avatar against the real ByteXL logo with a 94% visual match. Second, our NLP engine caught scam phrases in their bio demanding UPI payments. Third, our algorithm flagged the typosquatting affixes. Result: **96% CRITICAL THREAT**."*
* **[1:45 – 2:30] The Knockout Punch (Automated Takedown):**  
  *"We don't just alert the brand; we resolve it. With one click on 'Generate Takedown Notice', AegisMark AI compiles forensic timestamps, side-by-side evidence, and generates a pre-formatted legal Cease & Desist package ready for Meta and Google abuse desks."*
* **[2:30 – 3:00] Market & VC Appeal (Kampus.vc Focus):**  
  *"AegisMark AI is built as a B2B SaaS platform for every venture-backed startup, university, and financial institution. Our vector search architecture scales to millions of assets with sub-second latency. We are protecting the future of digital brands. Thank you!"*
