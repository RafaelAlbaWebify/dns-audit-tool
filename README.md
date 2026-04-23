# DNS Audit Tool

A practical PowerShell-based DNS auditing tool with a WPF GUI, designed for fast operational diagnostics and CSV reporting.

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
