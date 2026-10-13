---
name: cyber-dashboard-viz
description: Component patterns and visualization guidelines for cybersecurity dashboards, threat radars, risk score gauges, and live incident feeds using Tremor, Recharts, and Tailwind.
---

# Cyber Dashboard & Visual Telemetry Guide

Use this skill to build dark-mode, high-impact cybersecurity dashboards that impress judges and enterprise clients.

## 1. Recommended Color Palette (SOC / Cyber Theme)
* Background: `#090d16` (Deep Obsidian / Midnight)
* Surface Cards: `#111827` (Dark Navy Gray) with 1px border `#1f2937`
* Critical Risk (90-100%): `#ef4444` (Vibrant Crimson Red)
* High Risk (70-89%): `#f97316` (Neon Amber Orange)
* Medium Risk (40-69%): `#eab308` (Cyber Yellow)
* Low Risk / Safe: `#10b981` (Emerald Green)
* Brand / Accent: `#3b82f6` or `#06b6d4` (Electric Cyan)

## 2. Key Dashboard Layout Sections
1. **Hero Metric KPI Strip:**
   * Active Monitored Brands (e.g. `12`)
   * Total Scanned Accounts (`14,820`)
   * Critical Threats Detected (`8`)
   * Auto-Takedowns Sent (`5`)
2. **Interactive Threat Scanner:**
   * Target input field: Brand Name & URL/Handle.
   * Big "Scan & Analyze" button with pulsing radar animation.
3. **Split Comparison View (Original vs Suspect):**
   * Left Card: Verified Brand Asset (Official Logo, Handle, Bio).
   * Right Card: Detected Impersonator (Cropped Logo with heatmap, highlighted scam text).
   * Center Badge: Big Circular SVG Gauge showing **94% CRITICAL**.
4. **Action Center:**
   * "Generate Takedown Notice" (Modal previewing legal cease & desist).
   * "Export Forensic Report (PDF)".