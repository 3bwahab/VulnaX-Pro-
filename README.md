# VulnaX-Pro

<p align="center">
  <h3 align="center">Enterprise Vulnerability Assessment Framework</h3>
  <p align="center">
    Attack Surface Discovery • Technology Intelligence • Vulnerability Correlation • Attack Path Analysis • Professional Reporting
  </p>
</p>

---

## Overview

VulnaX-Pro is an enterprise-grade vulnerability assessment framework designed for authorized security testing, bug bounty research, attack surface management, and security assessments.

Unlike traditional tool wrappers, VulnaX-Pro provides a unified intelligence pipeline that combines:

* Asset Discovery
* Service Fingerprinting
* Technology Detection
* Deep Crawling
* JavaScript Intelligence
* API Discovery
* Authentication Mapping
* Vulnerability Correlation
* CVE Intelligence
* Attack Path Analysis
* AI-Assisted Security Analysis
* Commercial-Grade Reporting

The framework is designed as a standalone Python platform that executes locally without requiring:

* SaaS infrastructure
* Web applications
* Kubernetes
* Docker
* External databases
* Distributed services

Everything runs from a single Python process while maintaining a modular enterprise architecture.

---

## Key Features

### Asset Intelligence

* Multi-source asset discovery
* Subdomain enumeration
* DNS intelligence
* Live host validation
* Service enumeration
* Port intelligence

### Technology Intelligence

* Framework fingerprinting
* Web stack identification
* JavaScript analysis
* Technology correlation
* Infrastructure mapping

### Attack Surface Mapping

* Deep crawling
* API discovery
* Endpoint extraction
* Authentication mapping
* Hidden resource discovery

### Vulnerability Intelligence

* CVE correlation
* Configuration assessment
* Exposure detection
* Risk scoring
* Evidence collection

### Attack Path Analysis

* Surface graph generation
* Attack chain modeling
* Lateral movement analysis
* Critical path identification

### AI Security Analyst

* Finding summarization
* Risk explanation
* Remediation generation
* Executive reporting
* Technical reporting

### Professional Reporting

* HTML reports
* Markdown reports
* JSON exports
* Executive summaries
* Technical evidence packages

---

# Architecture

## Core Engines

| Engine                   | Purpose                         |
| ------------------------ | ------------------------------- |
| AssetDiscovery           | Attack surface enumeration      |
| AssetValidation          | Live asset verification         |
| ServiceFingerprint       | Service detection               |
| TechnologyDetection      | Technology stack identification |
| DeepCrawler              | Website crawling                |
| JavaScriptIntelligence   | JS endpoint extraction          |
| ApiDiscovery             | API identification              |
| AuthenticationMapping    | Authentication analysis         |
| ConfigurationAssessment  | Misconfiguration detection      |
| VulnerabilityCorrelation | Finding correlation             |
| CVEIntelligence          | CVE enrichment                  |
| AttackSurfaceGraph       | Graph generation                |
| RiskScoring              | Severity calculation            |
| AttackPath               | Attack chain analysis           |
| AIAnalyst                | AI-assisted reasoning           |
| Reporting                | Report generation               |

---

# Integrated Tool Ecosystem

VulnaX-Pro uses a unified adapter architecture.

Supported integrations include:

### Discovery

* subfinder
* amass
* assetfinder
* findomain
* chaos

### Validation

* httpx
* dnsx
* naabu

### Crawling

* katana

### Vulnerability Assessment

* nuclei
* dalfox
* sqlmap

### Content Discovery

* feroxbuster
* dirsearch

### Visual Intelligence

* gowitness

### Technology Detection

* wappalyzer

Missing tools are optional.

Built-in Python fallback engines are used whenever possible.

---

# Quick Start

## Clone Repository

```bash
git clone https://github.com/3bwahab/VulnaX-Pro.git
cd VulnaX-Pro
```

## Create Virtual Environment

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Verify Installation

```bash
python main.py doctor
```

## Run Your First Scan

```bash
python main.py scan -d example.com --profile quick
```

---

# Installation Health Check

Run:

```bash
python main.py doctor
```

Example:

```text
VulnaX-Pro - Tool Health

┏━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Tool        ┃ Status    ┃ Version          ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ subfinder   │ available │ 2.7.1            │
│ httpx       │ available │ 1.7.0            │
│ naabu       │ available │ 2.3.0            │
│ nuclei      │ available │ 3.4.0            │
│ katana      │ available │ 1.1.2            │
└─────────────┴───────────┴──────────────────┘
```

Missing tools are reported but do not prevent execution.

---

# AI Provider Configuration

VulnaX-Pro supports multiple AI providers.

Configure one or more API keys:

```bash
ANTHROPIC_API_KEY=
OPENROUTER_API_KEY=
DEEPSEEK_API_KEY=
KIMI_API_KEY=
GEMINI_API_KEY=
```

Verify:

```bash
python main.py doctor
```

Example:

```text
AI Providers

┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Provider   ┃ Status  ┃ Model                  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ anthropic  │ key set │ claude-opus-4-8        │
│ openrouter │ key set │ deepseek/deepseek-chat │
│ deepseek   │ key set │ deepseek-chat          │
│ kimi       │ key set │ moonshot-v1-8k         │
│ gemini     │ key set │ gemini-1.5-flash       │
└────────────┴─────────┴────────────────────────┘
```

Provider selection automatically falls back when a provider is unavailable.

---

# Command Line Interface

## Scan

```bash
python main.py scan --scope config/scope.yaml --profile standard
```

## Quick Scan

```bash
python main.py scan -d example.com --profile quick
```

## Deep Scan

```bash
python main.py scan -d example.com --profile deep
```

## Resume Scan

```bash
python main.py resume --scan-id <scan-id>
```

## Generate Reports

```bash
python main.py report \
  --scan-id <scan-id> \
  --format html,md,json
```

## Asset Inventory

```bash
python main.py inventory --scan-id <scan-id>
```

## Tool Health Check

```bash
python main.py doctor
```

## Update Resources

```bash
python main.py tools update
```

## Validate Configuration

```bash
python main.py config validate
```

---

# Live Dashboard

During execution VulnaX-Pro displays a professional real-time dashboard.

```text
╔══════════════════════════════════════════════════════════════════════╗
║ VulnaX-Pro · scan 2026-06-15-ab12 · scope: *.example.com          ║
╠══════════════════════════════════════════════════════════════════════╣
║ Assets Found ............... 1,248                                ║
║ Live Assets .................. 384                                ║
║ Technologies Detected ....... 127                                 ║
║ URLs Collected ............ 14,532                                ║
║ APIs Identified ............ 3,241                                ║
║ Validated Findings ............ 18                                ║
║ Critical Attack Paths .......... 3                                ║
╚══════════════════════════════════════════════════════════════════════╝
```

Raw tool output is hidden by default.

Users receive a curated enterprise experience rather than command-line noise.

---

# Documentation

| Document                   | Description           |
| -------------------------- | --------------------- |
| 00_OVERVIEW                | System overview       |
| 01_DIRECTORY_STRUCTURE     | Project structure     |
| 02_ARCHITECTURE            | Internal architecture |
| 03_ENGINES                 | Engine specifications |
| 04_INTEGRATIONS            | Tool adapters         |
| 05_CLI                     | CLI architecture      |
| 06_DATA_MODELS             | Data schemas          |
| 07_PAYLOAD_INTELLIGENCE    | Resource intelligence |
| 08_REPORTING               | Reporting subsystem   |
| 09_ATTACK_PATH             | Attack path analysis  |
| 10_DIAGRAMS                | Architecture diagrams |
| 11_PLUGINS                 | Plugin system         |
| 12_SCALING_TESTING_ROADMAP | Development roadmap   |

---

# Development Status

Current Stage:

**Architecture & Enterprise Design Phase**

Implementation is progressing according to:

```text
docs/12_SCALING_TESTING_ROADMAP.md
```

Current focus areas:

* Engine implementation
* Adapter layer development
* Correlation engine
* Attack path engine
* Reporting pipeline
* AI analyst integration

---

# Security & Authorization

VulnaX-Pro is designed exclusively for authorized security testing.

Allowed use cases include:

* Bug bounty programs
* Assets you own
* Internal security assessments
* Contracted penetration tests
* Written customer engagements

The framework requires a valid scope definition and refuses out-of-scope targets at the integration layer.

Users are solely responsible for ensuring proper authorization before conducting any assessment.

---

# License

This project is provided for educational, research, and authorized security assessment purposes.

Always obtain proper authorization before testing any target.
