# OPSCORE Roadmap

OPSCORE is my planned Infrastructure / Production Operations workbench.

The DNS Audit Tool is the first OPSCORE module. I am keeping this repository focused on DNS, while using it as the starting point for a broader infrastructure and production evidence system.

## Why OPSCORE Exists

DNS is important, but it is not enough to represent the full Infrastructure / Production Operations area.

Real production and infrastructure incidents usually involve several layers:

```text
User or business symptom
  -> application or website
  -> identity / permissions
  -> DNS / name resolution
  -> certificate / TLS
  -> HTTP / service response
  -> port / connectivity
  -> server / VM / service state
  -> database, API or dependency
  -> monitoring / backup / history evidence
  -> escalation, RCA or change-control path
```

OPSCORE is intended to organize that evidence into support-ready outputs.

## Positioning

| Area | Flagship | Target role |
|---|---|---|
| IPPO - Infrastructure / Production Operations | OPSCORE | Infrastructure / Production Operations Engineer |

## Current Module

### Module 01 - DNS Evidence and Consistency Audit

Repository: `dns-audit-tool`

Purpose:

- Query DNS zones and DNS servers.
- Classify missing PTR records, PTR mismatches, shared IPs, stale records, forward drift and alias patterns.
- Export CSV evidence.
- Support tickets, validation notes and escalation handoffs.

## Planned OPSCORE Modules

### Module 02 - HTTP / Service Reachability Evidence

Goal:

- Check key URLs or internal service endpoints.
- Capture status code, response time, redirects and basic availability evidence.
- Export a small support report.

### Module 03 - SSL / Certificate Evidence

Goal:

- Check certificate expiry, issuer, subject, SANs and mismatch signals.
- Highlight expiring or incorrect certificates.
- Produce evidence suitable for renewal/escalation tickets.

### Module 04 - Port / Connectivity Evidence

Goal:

- Test whether expected service ports are reachable.
- Separate DNS failure, timeout, refused connection and reachable service states.
- Support firewall/network escalation packages.

### Module 05 - Dependency Map

Goal:

- Map a business or user-facing service to its dependencies.
- Example: website -> DNS -> certificate -> HTTP endpoint -> backend service -> database/API.
- Help explain what evidence was checked and what remains unknown.

### Module 06 - Incident Timeline Builder

Goal:

- Capture timestamps, symptoms, evidence, actions, owner notes and escalation points.
- Produce a clean incident timeline for handover or RCA.

### Module 07 - RCA / Escalation Report Generator

Goal:

- Convert evidence into a structured report:
  - impact
  - symptoms
  - evidence checked
  - likely cause
  - alternatives
  - safe next steps
  - what not to change yet
  - escalation note

## Boundaries

OPSCORE should remain evidence-first and safe by design.

It should not:

- perform blind remediation
- change DNS records automatically
- change firewall rules
- restart services without explicit design and approval
- bypass change control
- pretend to confirm business impact without validation

## Near-Term Next Step

The next practical step is not to create a large empty OPSCORE repository.

The next practical step is to extend DNS Audit Tool with a small, public-safe evidence workflow:

```text
DNS finding
  -> validation checklist
  -> ticket note
  -> escalation note
  -> sample report
```

After that, OPSCORE can become its own repository when there is at least one additional working module beyond DNS.
