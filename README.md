# DNS Audit Tool

PowerShell-based DNS auditing tool with a WPF GUI for operational diagnostics, finding classification, and CSV reporting.

This project is part of my Rafael Alba IT Lab: practical IT Operations tools focused on infrastructure troubleshooting, evidence collection, documentation, and repeatable support workflows.

## Current Status

Working public portfolio version.

The tool is designed for Windows environments where the operator has access to DNS Server / RSAT tooling and permission to query the target DNS servers. The public version is sanitized for external sharing and uses neutral example values.

## Problem It Solves

DNS issues often appear as unrelated support symptoms:

- authentication failures
- intermittent application errors
- Outlook or Teams connection issues
- slow access to internal resources
- inconsistent name resolution
- confusing device or service reachability reports

These problems can accumulate after migrations, rebuilds, device replacements, decommissioning, DHCP changes, server moves, or incomplete cleanup work. A lightweight audit gives support teams a faster way to classify findings and decide what needs validation.

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

A user reports intermittent authentication or application access issues.

Initial checks show that the system is reachable and basic network connectivity works, but the symptoms remain inconsistent. Running the DNS audit reveals missing PTR records and forward/reverse mismatches for affected hosts.

That evidence helps the support team explain the issue more clearly, validate whether DNS cleanup is needed, and decide the next action without guessing.

## Features

- WPF GUI for interactive use
- Multi-zone support
- CSV export by finding type and by zone
- Built-in debug logging
- Quick mode to skip ping checks
- Finding classification with severity, category, recommended action, and validation guidance
- Portfolio-friendly output that can be attached to tickets, handovers, or lab notes

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

## Safety and Scope

This tool is read-only from the DNS audit perspective. It is intended to collect evidence and classify possible issues, not to automatically remediate DNS records.

It does not:

- delete records
- modify zones
- perform automated remediation
- replace change-control procedures
- confirm business impact without validation

## Homelab / FactoryOps Use

This project is a good fit for the planned FactoryOps homelab. It can be used to simulate and document realistic DNS-related support scenarios, such as:

- stale host records after device replacement
- missing PTR records causing confusing support evidence
- forward/reverse mismatch after server rebuild
- shared IP or alias confusion during service migration
- application access issue where DNS evidence helps escalation

A future lab scenario should include the simulated issue, the audit output, the support ticket notes, the likely cause, validation steps, and the final runbook entry.

## Portfolio Value

This project demonstrates practical PowerShell tooling, infrastructure troubleshooting, DNS support awareness, evidence collection, CSV reporting, and support-focused documentation.

It supports my public positioning around IT Operations, Systems Support, Microsoft 365 / Entra ID troubleshooting, infrastructure diagnostics, and practical automation.

## Next Improvements

- Add screenshots of the WPF GUI.
- Add a short demo walkthrough using sanitized sample data.
- Add a FactoryOps homelab DNS mismatch scenario.
- Add example ticket notes and escalation notes based on generated CSV findings.
- Add a small validation checklist for reviewing findings safely.

## License

MIT

## Author

Rafael Alba
