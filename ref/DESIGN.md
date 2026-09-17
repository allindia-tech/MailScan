---
name: MailTrace Workstation
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#464554'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#777586'
  outline-variant: '#c7c4d7'
  surface-tint: '#5148d7'
  primary: '#2a14b4'
  on-primary: '#ffffff'
  primary-container: '#4338ca'
  on-primary-container: '#c1beff'
  inverse-primary: '#c3c0ff'
  secondary: '#0058be'
  on-secondary: '#ffffff'
  secondary-container: '#2170e4'
  on-secondary-container: '#fefcff'
  tertiary: '#323a4f'
  on-tertiary: '#ffffff'
  tertiary-container: '#495167'
  on-tertiary-container: '#bcc4de'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#e3dfff'
  primary-fixed-dim: '#c3c0ff'
  on-primary-fixed: '#100069'
  on-primary-fixed-variant: '#372abf'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#adc6ff'
  on-secondary-fixed: '#001a42'
  on-secondary-fixed-variant: '#004395'
  tertiary-fixed: '#dae2fd'
  tertiary-fixed-dim: '#bec6e0'
  on-tertiary-fixed: '#131b2e'
  on-tertiary-fixed-variant: '#3f465c'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 2.25rem
    fontWeight: '600'
    lineHeight: 2.75rem
    letterSpacing: -0.025em
  headline-lg:
    fontFamily: Geist
    fontSize: 1.75rem
    fontWeight: '600'
    lineHeight: 2.25rem
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 1.375rem
    fontWeight: '600'
    lineHeight: 1.75rem
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Geist
    fontSize: 1.25rem
    fontWeight: '600'
    lineHeight: 1.75rem
    letterSpacing: -0.015em
  body-lg:
    fontFamily: Geist
    fontSize: 1rem
    fontWeight: '400'
    lineHeight: 1.5rem
  body-md:
    fontFamily: Geist
    fontSize: 0.875rem
    fontWeight: '400'
    lineHeight: 1.375rem
  body-sm:
    fontFamily: Geist
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1.125rem
  label-lg:
    fontFamily: JetBrains Mono
    fontSize: 0.875rem
    fontWeight: '500'
    lineHeight: 1.25rem
    letterSpacing: -0.01em
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 0.75rem
    fontWeight: '500'
    lineHeight: 1rem
    letterSpacing: 0.02em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 0.6875rem
    fontWeight: '500'
    lineHeight: 0.875rem
    letterSpacing: 0.04em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-desktop: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

The design system embodies a forensic-grade, intelligence-centered workstation architecture. It delivers absolute clarity, evidentiary certainty, and operational composure to cybersecurity analysts, digital forensics teams, and incident response engineers inspecting email payloads, DKIM/SPF/DMARC telemetry, and routing chains.

The aesthetic fuses **Modern Enterprise Utility** with **Precision Forensics**:
- **Purity and Legibility:** Crisp slate-white viewports eliminate visual fog. Critical signals, malicious artifacts, and cryptographic verification statuses emerge instantly without cognitive overload.
- **Architectural Grounding:** Hairline boundaries and strict geometric divisions echo hardware network analyzers and terminal instruments, refined into an authoritative executive dashboard.
- **Evidentiary Integrity:** The tone is clinical, objective, and unflinchingly calm under crisis.

## Colors

The palette balances clinical slate-white surfaces against high-contrast forensic status indicators:

- **Primary & Secondary (`#4338ca` / `#3b82f6`):** Deep indigo drives core interactive mechanisms, focused tree-nodes, and active session states; cobalt handles exploratory links, active packet inspectors, and primary telemetry tabs.
- **Neutral Tier:** Grounded in a cool slate continuum. `#0f172a` serves as the primary text and high-contrast title tone. `#475569` supports secondary metadata and structural column titles, with `#64748b` for subtle timestamps, headers, and auxiliary details.
- **Surfaces:** Clean layered planes utilizing `#ffffff` (card elevations and active table cells), `#f8fafc` (primary workstation canvas), and `#f1f5f9` (rail panels, inspection sidebars, and inactive inputs). Hairline borders utilize `#e2e8f0`.
- **Diagnostic Semantics:**
  - *Pass / Cryptographically Verified:* `#059669` (surface fill `#ecfdf5`, border `#a7f3d0`).
  - *Critical Malice / Forgery / Tamper:* `#e11d48` (surface fill `#fff1f2`, border `#fecdd3`).
  - *Evasion / Warning / Mismatch:* `#d97706` (surface fill `#fffbeb`, border `#fde68a`).
  - *Informational / Route Transit:* `#0284c7` (surface fill `#f0f9ff`, border `#bae6fd`).

## Typography

The type system pairs **Geist** for crisp, proportional interface mechanics and natural human reading with **JetBrains Mono** for forensic artifacts, hashes, IP hops, RFC headers, and verification tokens.

- **Primary Interface (Geist):** Handles all layout hierarchy, modal framing, analytical descriptions, and workflow triggers. Tight tracking on headlines commands authority without shouting.
- **Forensic & Data Layer (JetBrains Mono):** Reserved for raw email headers (`Received-SPF`, `DKIM-Signature`), CIDR blocks, raw MIME analysis, hex strings, and diagnostic tags. This guarantees columnar alignment and eliminates character ambiguity (e.g., distinguishing zero from 'O', one from 'l').

## Layout & Spacing

The workstation adopts a multi-tier fixed-and-fluid grid model tailored for dense evidentiary workflows:

- **Desktop Structure:** 
  - Left navigation rail: Fixed at `240px` (or collapsible to `64px`).
  - Investigation panel: Fluid 12-column subgrid spanning evidence lists and telemetry charts with `1.5rem` gutters.
  - Right-hand forensic inspector / raw header pane: Fixed-fluid split at `380px` to `480px` for persistent deep-dive scrutiny.
- **Rhythm & Padding:** Dense data architecture requires precise spacing:
  - `space-xs` (4px) and `space-sm` (8px) for tabular row padding, status pills, and micro-metric grouping.
  - `space-md` (12px) for card interiors and form controls.
  - `space-lg` (20px) for container splits and module definitions.
- **Breakpoints:**
  - Desktop (`>=1280px`): Full 3-pane workstation mode.
  - Tablet (`768px - 1279px`): Right forensic pane converts to an off-canvas slide-out sheet; grid shifts to 8 columns with `1rem` gutters.
  - Mobile (`<768px`): Linear single-column stack; sticky navigation shifts to a persistent bottom utility bar.

## Elevation & Depth

Visual separation relies on sharp tonal layers and micro-hairline borders rather than dramatic blur effects or heavy drop shadows:

- **Flat Precision Canvas:** The master viewport rests at `background: #f8fafc`. Workspace panels, analysis boards, and inspector cards lift directly onto pure `#ffffff` with a crisp `1px solid #e2e8f0` structural boundary.
- **Subtle Ambient Definition:** For overlays, slide-over raw-log drawers, and floating tooltips, use low-opacity slate shadow geometry:
  - *Tier 0 (Embedded Elements):* No shadow; separated purely via `#e2e8f0` borders and `#f1f5f9` inset fills.
  - *Tier 1 (Surface Cards & Header Bars):* `0 1px 2px 0 rgba(15, 23, 42, 0.04)`.
  - *Tier 2 (Dropdowns, Active Popovers):* `0 4px 6px -1px rgba(15, 23, 42, 0.07), 0 2px 4px -2px rgba(15, 23, 42, 0.05)`.
  - *Tier 3 (Forensic Modals & Slide-out Panels):* `0 20px 25px -5px rgba(15, 23, 42, 0.08), 0 8px 10px -6px rgba(15, 23, 42, 0.04)`.

## Shapes

The interface adheres to a calibrated `Soft` geometric language (`roundedness: 1`):

- Base controls, input triggers, data pills, and buttons leverage `0.25rem` (4px) radius to preserve a sharp, clinical edge.
- Cards, modal containers, and forensic viewer viewports scale up to `0.5rem` (8px) via `rounded-lg`.
- Strict structural elements—such as raw code blocks, hex dumps, and split-screen header grids—remain framed in crisp 4px corners, maintaining an engineered, zero-fluff appearance.

## Components

### Buttons
- **Primary:** `#4338ca` background, `#ffffff` text, 4px radius, `0.75rem` vertical / `1rem` horizontal padding. Focused states display a `2px` ring in `#3b82f6` with `2px` offset.
- **Secondary / Ghost:** Transparent surface with `1px solid #e2e8f0`, `#0f172a` text. Hover transitions to `#f8fafc` with border `#cbd5e1`.
- **Destructive / Flag:** `#e11d48` text on `#fff1f2` background with `#fecdd3` border for quarantine, purge, or escalation actions.

### Forensic Threat Badges & Chips
- **Layout:** Monospaced (`JetBrains Mono`, `0.6875rem`), uppercase, `4px` padding inline, `2px` padding block, subtle border.
- **Verified / Clean:** Background `#ecfdf5`, border `#a7f3d0`, text `#065f46`. Prefix with a crisp `●` indicator.
- **Critical Tamper / Threat:** Background `#fff1f2`, border `#fecdd3`, text `#9f1239`.
- **Evasion / SPF Neutral:** Background `#fffbeb`, border `#fde68a`, text `#92400e`.

### Inputs & Trace Query Fields
- **Container:** Background `#ffffff`, border `1px solid #cbd5e1`, `0.25rem` radius, text `#0f172a`.
- **Focus:** Border shifted to `#4338ca` with `0 0 0 1px #4338ca`.
- **Trace Filter Bar:** Prepended with monospaced parameter chips (`dmarc:fail`, `ip:192.168.0/24`) rendered in `#f1f5f9` with `#475569` labels.

### Tables & Data Grids
- **Header:** Background `#f8fafc`, `1px solid #e2e8f0`, label text in `#475569` with `JetBrains Mono` at `0.75rem`, all-caps.
- **Row:** Alternating clean `#ffffff` and subtle hover `#f8fafc`. Cell height pinned to `40px` for high scan density. Dividing borders `1px solid #f1f5f9`.

### Forensic Trace Timeline (Specialized Component)
- **Node Spine:** `2px` vertical spine in `#e2e8f0` connecting mail transport hops.
- **Hop Capsule:** `#ffffff` surface with `1px solid #e2e8f0`. Left edge features a `3px` solid status bar (Green for intact SPF/DKIM, Red for invalid relay, Amber for unauthenticated transit).
- **Metadata Viewport:** Monospaced timestamps (`UTC`), client latency metrics (`+42ms`), and IP resolution tags displayed via `label-sm`.