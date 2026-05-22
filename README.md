# DNS Audit Tool

PowerShell-based DNS auditing tool with a WPF GUI for operational diagnostics and CSV reporting.

This project is part of my Rafael Alba IT Lab, where I build practical tools and environments for real-world IT troubleshooting.

## Problem It Solves

DNS issues often appear as unrelated support symptoms: authentication failures, intermittent application errors, Outlook or Teams connection issues, slow access to internal resources or inconsistent name resolution.

This tool helps expose DNS inconsistencies that are easy to miss during day-to-day support work.

## What It Checks

- Missing PTR records
- PTR mismatches
- Multiple PTR records per IP
- Shared IP usage
- Multiple aliases pointing to the same target
- Potentially stale records
- Forward resolution drift
- Zone-level summary information

## Why It Matters

Many DNS problems do not trigger obvious alerts. They accumulate quietly after migrations, rebuilds, device replacements or decommissioning. A lightweight audit gives support teams a faster way to classify findings and decide what needs validation.

## Example Scenario

A user reports intermittent authentication issues.

Initial checks show that network connectivity works and the system is reachable. Running the audit reveals missing PTR records and forward/reverse mismatches for affected hosts. That evidence helps explain inconsistent name resolution and gives the support team a clear next action.

## Features

- WPF GUI for interactive use
- Multi-zone support
- CSV export by finding type and by zone
- Built-in debug logging
- Quick mode to skip ping checks
- Finding classification with severity, category, recommended action and validation guidance

## Requirements

- Windows
- PowerShell 5.1 or later
- DNS Server module or RSAT tools
- Network access to the DNS servers being queried

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
- This tool is intended as a fast audit and diagnostics layer, not a replacement for enterprise DNS management platforms.

## Portfolio Value

This project demonstrates practical PowerShell tooling, infrastructure troubleshooting, evidence collection, CSV reporting and support-focused documentation.

## Public Release Note

This public version is sanitized for external sharing and uses neutral example values in the GUI defaults.

## License

MIT

## Author

Rafael Alba
