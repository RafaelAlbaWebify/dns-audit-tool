# DNS Audit Tool

> Read-only DNS evidence and consistency audit for infrastructure support.

DNS Audit Tool is a PowerShell WPF utility for collecting DNS evidence, classifying possible inconsistencies and exporting ticket-ready CSV reports.

It is a specialist supporting module for [OPSCORE](https://github.com/RafaelAlbaWebify/opscore), not a replacement for enterprise DNS management platforms.

## Problem it addresses

DNS problems often appear as unrelated support symptoms:

- intermittent application or authentication failures;
- inconsistent name resolution;
- confusing reachability reports;
- stale records after migrations or device replacement;
- forward and reverse lookup disagreement.

The tool provides a repeatable way to gather evidence before deciding whether cleanup, deeper investigation or escalation is required.

## Workflow

```text
DNS zones and servers
  -> read-only DNS queries
  -> forward / reverse / alias / stale-record checks
  -> finding classification
  -> CSV evidence exports
  -> ticket notes or escalation handover
```

## Checks

- Missing PTR records
- PTR mismatches
- Multiple PTR records for one IP
- Shared IP usage
- Multiple aliases for one target
- Potentially stale records
- Forward-resolution drift
- Zone-level summaries

## Requirements

- Windows
- PowerShell 5.1 or later
- DNS Server module or RSAT tools
- Network access to the DNS servers
- Permission to query the relevant zones

## Run

```powershell
.\DNSAudit_v4.2.0.ps1
```

Then:

1. Select the output folder.
2. Enter the DNS zones and servers.
3. Adjust the options where needed.
4. Run the audit.
5. Review the CSV files and debug log.
6. Validate findings before treating them as confirmed incidents.

## Output

Typical files include:

- `Summary.csv`
- `Missing_PTR.csv`
- `PTR_Mismatch.csv`
- `Stale_Record.csv`
- `Potential_Stale_Unreachable.csv`
- `Shared_IP.csv`
- `Forward_Drift.csv`
- `PTR_Multiple.csv`
- `Zone_Summary.csv`

See [`examples/sample-output.md`](examples/sample-output.md) for a readable explanation of sample findings.

## Interpretation notes

- Failed ping does not prove that a host is inactive because ICMP may be blocked.
- Shared IPs and multiple aliases may be valid by design.
- A stale-looking record must be validated before removal.
- Forward/reverse mismatches may reflect transitional environments rather than an active incident.
- Findings improve the evidence available to support; they do not independently confirm business impact or root cause.

## Safety boundary

The audit is read-only. It does not:

- delete or modify records;
- change zones;
- perform automatic remediation;
- replace change control;
- confirm an incident without contextual validation.

## Portfolio value

This project demonstrates practical PowerShell GUI work, DNS troubleshooting awareness, structured evidence collection, finding classification and support-ready reporting.

## License

MIT

## Author

Rafael Alba
