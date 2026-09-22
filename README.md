# 🛡️ JobKavach / Fake Offer Letter & Phishing Inspector

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/framework-Streamlit-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, modular security intelligence tool engineered for SOC analysts and job seekers to inspect and expose fraudulent employment offers, advance-fee schemes, equipment purchase traps, and deceptive recruiter domain infrastructure.

---

## 🚀 Key Features

- **Multi-Vector NLP & Regex Text Parser**: Linear-time $O(N)$ text scanning engine built to resist ReDoS (Regular Expression Denial of Service). Detects check overpayment schemes, advance fees, urgent coercion, and free webmail impersonation.
- **DNS & WHOIS Domain Verification**: Extracts root domains, checks registration age in days against a 180-day threshold, and identifies WHOIS privacy proxies with comprehensive socket-level timeout protection.
- **Dynamic Scam Threat Index (0–100%)**: Deterministic weighted scoring algorithm that outputs color-coded risk tiers (`CRITICAL`, `SUSPICIOUS`, `LOW RISK`).
- **Immutable SQLite Audit Ledger**: Stores complete scan histories, SHA-256 payload integrity hashes, and structured IoC telemetry with WAL mode enabled.
- **Executive SOC Dashboard**: Streamlit interface with threat meters, color-coded callouts, MITRE ATT&CK mapping, and automated evaluation sample loaders.

---

## 📂 Project Architecture

```text
├── src/
│   ├── config/              # Centralized threat weights, regex signatures, and MITRE tags
│   ├── database/            # SQLite connection pool, WAL mode, schema init, audit logging
│   ├── models/              # Strongly-typed dataclasses for analysis results
│   ├── services/            # Core business engines (Text Parser, Domain Verifier, Scoring Engine)
│   └── ui/                  # Modular Streamlit views, components, and SOC dark theme
├── tests/                   # Automated unit and integration tests
├── app.py                   # Main application entry point
├── requirements.txt         # Project dependencies
└── .gitignore               # Excludes databases, caches, and secrets
```

---

## 🛠️ Quickstart & Installation

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Linux / macOS
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
streamlit run app.py
```

---

## 📊 Threat Scoring Rubric

| Indicator Category | Weight | Rationale |
| :--- | :--- | :--- |
| **Domain Age < 180 Days** | **+40%** | Newly registered domains are disproportionately used in phishing infrastructure. |
| **Specific Financial Keywords** | **+20% each** | Legitimate employers do not transact via P2P (Zelle, Venmo) or cryptocurrency. |
| **Masked WHOIS Privacy** | **+20%** | Conceals registrant identity to prevent corporate attribution. |
| **Pay-for-Equipment Phishing** | **+20%** | Classic check overpayment scam targeting remote workers. |
| **Advance Fee / Security Deposit** | **+20%** | Fraudulent upfront charge for screening, visas, or onboarding. |
| **Free Webmail Recruiter** | **+25%** | Impersonation using public `@gmail` or `@yahoo` addresses. |
| **Coercive Urgency** | **+15%** | Pressure tactics demanding action within 24 hours. |

---

## 🔒 Security & Compliance

- **No SQL Injection**: Fully parameterized queries across all database operations.
- **ReDoS Protected**: Regex patterns avoid nested quantifiers.
- **Defensive Timeouts**: WHOIS socket lookups avoid thread blocking.
