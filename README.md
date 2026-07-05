# DNS Audit Tool

> OPSCORE DNS Module - DNS evidence and consistency audit for infrastructure support.

DNS Audit Tool is my first **OPSCORE** module.

It is a PowerShell-based DNS auditing tool with a WPF GUI for operational diagnostics, finding classification and CSV reporting. I use it to demonstrate practical infrastructure troubleshooting, DNS evidence collection, support documentation and repeatable audit workflows.

This repository remains focused on DNS. It does not try to represent the whole Infrastructure / Production Operations area by itself. The broader flagship is **OPSCORE**, my planned infrastructure and production operations workbench.

## Flagship Area

| Area | Flagship | Module | Target role |
|---|---|---|---|
| IPPO - Infrastructure / Production Operations | OPSCORE | DNS Audit Tool | Infrastructure / Production Operations Engineer |

## Current Status

Current status: **working public portfolio version**.

The tool is designed for Windows environments where the operator has access to DNS Server / RSAT tooling and permission to query the target DNS servers. The public version is sanitized for external sharing and uses neutral example values.

## Problem It Solves

DNS issues often appear as unrelated support symptoms:

- authentication failures
- intermittent application errors
- Outlook or Teams connection issues
- slow access to internal resources
- inconsistent name resolution
- confusing device or service reachability reports

These problems can accumulate after migrations, rebuilds, device replacements, decommissioning, DHCP changes, server moves or incomplete cleanup work.

A lightweight DNS audit gives support teams a faster way to classify findings, validate evidence and decide what needs deeper investigation.

## Core Workflow

```text
DNS zones and DNS servers
  -> Read-only DNS queries
  -> Forward / reverse / alias / stale-record checks
  -> Finding classification
  -> CSV evidence exports
  -> Ticket notes, validation steps or escalation handoff
```

## What It Checks

- Missing PTR records
- PTR mismatches
- Multiple PTR records per IP
- Shared IP usage
- Multiple aliases pointing to the same target
- Potentially stale records
- Forward resolution drift
- Zone-level summary information

## Example Support Scenario

**Ticket:** A user reports intermittent authentication or application access issues.

Initial checks show that the system is reachable and basic network connectivity works, but the symptoms remain inconsistent. Running the DNS audit reveals missing PTR records and forward/reverse mismatches for affected hosts.

That evidence helps me explain the issue more clearly, validate whether DNS cleanup is needed, and decide the next action without guessing.

## Features

- WPF GUI for interactive use
- Multi-zone support
- CSV export by finding type and by zone
- Built-in debug logging
- Quick mode to skip ping checks
- Finding classification with severity, category, recommended action and validation guidance
- Portfolio-friendly output that can be attached to tickets, handovers or lab notes

## Requirements

- Windows
- PowerShell 5.1 or later
- DNS Server module or RSAT tools
- Network access to the DNS servers being queried
- Appropriate permission to query the DNS zones being reviewed

## Usage

Run the script from PowerShell:

```powershell
.\DNSAudit_v4.2.0.ps1
```

Then:

1. Select the output folder.
2. Enter the DNS zones and DNS servers.
3. Adjust options if needed.
4. Click **Run audit**.
5. Review the generated CSV files and debug log.
6. Validate findings before treating them as confirmed incidents.

## Output Files

The tool can generate outputs such as:

- `All_Records.csv`
- `Summary.csv`
- `Missing_PTR.csv`
- `PTR_Mismatch.csv`
- `Stale_Record.csv`
- `Potential_Stale_Unreachable.csv`
- `Shared_IP.csv`
- `Forward_Drift.csv`
- `PTR_Multiple.csv`
- `Zone_Summary.csv`
- debug log files

See [examples/sample-output.md](examples/sample-output.md) for a readable example of what the findings mean.

## Troubleshooting Notes

- ICMP can be blocked, so failed ping does not always mean a host is inactive.
- Shared IPs or multiple aliases may be valid by design and should be reviewed in context.
- A stale-looking record should be validated before removal.
- Forward/reverse mismatches can indicate cleanup issues, but they can also appear in transitional environments.
- This tool is intended as a fast audit and diagnostics layer, not a replacement for enterprise DNS management platforms.

## Safety and Boundaries

This tool is read-only from the DNS audit perspective. It is intended to collect evidence and classify possible issues, not to automatically remediate DNS records.

It does not:

- delete records
- modify zones
- perform automated remediation
- replace change-control procedures
- confirm business impact without validation

## OPSCORE Direction

OPSCORE will be my broader Infrastructure / Production Operations workbench.

DNS Audit Tool becomes the first module because DNS evidence is often part of larger incidents involving identity, applications, websites, internal services, certificates, connectivity and escalation.

Future OPSCORE modules may include:

- DNS evidence and consistency audit
- HTTP / service reachability checks
- SSL certificate expiry and mismatch checks
- port / connectivity evidence
- dependency mapping
- backup-awareness evidence
- incident timeline builder
- RCA and escalation report generator

## B2B / Contract Use

This tool can support future controlled B2B or contract work through my Irish LTD, Webify Digital Solutions Ltd, especially around:

- DNS/domain operational reviews
- infrastructure troubleshooting evidence
- support-ticket documentation
- migration or cleanup validation
- small-business website/domain health checks
- escalation-quality reports for technical providers

This repository is a public-safe portfolio tool. It should not be used to change production DNS without validation, approval and proper change control.

## Homelab / FactoryOps Use

This project is a good fit for my FactoryOps-style homelab work. It can be used to simulate and document realistic DNS-related support scenarios, such as:

- stale host records after device replacement
- missing PTR records causing confusing support evidence
- forward/reverse mismatch after server rebuild
- shared IP or alias confusion during service migration
- application access issue where DNS evidence helps escalation

A future lab scenario should include the simulated issue, the audit output, the support ticket notes, the likely cause, validation steps and the final runbook entry.

## Portfolio Value

This project demonstrates practical PowerShell tooling, infrastructure troubleshooting, DNS support awareness, evidence collection, CSV reporting and support-focused documentation.

It supports my public positioning around IT Operations, Infrastructure / Production Operations, Microsoft 365 / Entra ID troubleshooting, application support evidence and practical automation.

## Next Improvements

- Add screenshots of the WPF GUI.
- Add a short demo walkthrough using sanitized sample data.
- Add an OPSCORE roadmap document.
- Add a FactoryOps homelab DNS mismatch scenario.
- Add example ticket notes and escalation notes based on generated CSV findings.
- Add a small validation checklist for reviewing findings safely.

## License

MIT

## Author

Rafael Alba
