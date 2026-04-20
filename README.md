# DNS Audit Tool

A practical PowerShell-based DNS auditing tool with GUI, designed for real-world operations environments.

## 🚀 What it does

DNS Audit helps you quickly identify:

- Missing PTR records
- Forward / reverse inconsistencies
- Stale DNS records
- Potential decommissioned assets
- Duplicate IP usage
- Multiple CNAMEs pointing to the same target
- Forward resolution drift

Built for **speed, clarity and actionable results** — not just raw data.

---

## 🧠 Why this exists

Most DNS tools either:
- Dump raw data (hard to interpret), or
- Are enterprise-grade (expensive, complex, slow)

This tool focuses on:
- Fast audits
- Clear findings
- Operational usefulness

---

## ⚙️ Features

- GUI (WPF) — no need for CLI usage
- Multi-zone support
- Intelligent classification of findings
- Built-in CSV reporting:
  - Per zone
  - Per issue type
- Quick mode (skip ping for speed)
- Detailed debug logging

---

## 📊 Output

The tool generates structured reports:

- `All_Records.csv`
- `Summary.csv`
- `Missing_PTR.csv`
- `PTR_Mismatch.csv`
- `Stale_Record.csv`
- `Forward_Drift.csv`
- etc.

Each record includes:
- Severity
- Category
- Recommended action
- What to validate

---

## 🖥️ Requirements

- Windows
- PowerShell 5.1+
- DNS Server module (`Get-DnsServerResourceRecord`)

---

## ▶️ Usage

1. Open PowerShell
2. Run the script:

```powershell
.\DNSAudit_v1.0.0_Public.ps1

⚠️ Notes
ICMP (ping) may be blocked in some environments
"Unreachable" does not always mean inactive
Always validate findings before cleanup
🧩 Positioning

This is not a replacement for enterprise DNS tools.

It is a fast operational audit layer for:

Sysadmins
IT support
Infrastructure teams
