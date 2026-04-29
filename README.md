# DNS Audit Tool

A practical PowerShell-based DNS auditing tool with a WPF GUI, designed for fast operational diagnostics and CSV reporting.

## Real-world usage

This tool was designed based on common issues found in operational environments:

- DNS records that exist but do not resolve correctly
- Missing PTR records affecting reverse lookups
- Stale entries after system changes or decommissioning

These issues often do not generate alerts but can cause:
- authentication problems
- connectivity issues
- application failures

## Troubleshooting mindset

Instead of relying on alerts, this tool helps identify:

- silent inconsistencies
- mismatched forward/reverse records
- outdated configurations

This reflects how real-world IT issues often behave: subtle, not obvious, and cumulative.

## Example scenario

A user reports intermittent authentication issues.

Initial checks show:
- Network connectivity is working
- The system is reachable
- No obvious service failure

Running this tool reveals:
- Missing PTR records for the affected host
- Forward/reverse mismatch in DNS

This explains inconsistent name resolution, which can impact authentication and service communication.

This type of issue often goes unnoticed because:
- It does not trigger alerts
- It appears as a "random" failure

## Why this exists

Many DNS tools are either too heavyweight for quick troubleshooting or too raw to be immediately useful in day-to-day operations.

This tool focuses on:

- fast visibility
- practical findings
- minimal setup
- exportable results

## Features

- WPF GUI for interactive use
- Multi-zone support
- CSV export by finding type and by zone
- Built-in debug logging
- Quick mode to skip ping checks
- Finding classification with severity, category, recommended action, and validation guidance

## Findings detected

- Missing PTR records
- PTR mismatches
- Multiple PTR records per IP
- Shared IP usage
- Multiple aliases pointing to the same target
- Potentially stale records
- Forward resolution drift

## Requirements

- Windows
- PowerShell 5.1 or later
- DNS Server module / RSAT tools
- Network access to the DNS servers being queried

## Usage

Run the script from PowerShell:

```powershell
.\DNSAudit_v4.2.0.ps1
```

Then:

1. Select the output folder
2. Enter the DNS zones and DNS servers
3. Adjust options if needed
4. Click **Run audit**

## Output

The tool generates outputs such as:

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

## Notes

- ICMP can be blocked in some environments, so failed ping does not necessarily mean a host is inactive.
- Some findings, such as shared IPs or multiple aliases, may be valid by design and should be reviewed in context.
- This tool is intended as a fast audit and diagnostics layer, not as a replacement for enterprise DNS management platforms.

## Public release note

This public version is sanitized for external sharing and uses neutral example values in the GUI defaults.

## License

MIT

## Author

Rafael Alba
