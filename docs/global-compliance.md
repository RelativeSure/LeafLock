---
title: "Global Compliance"
slug: compliance
summary: "Checklist for operating LeafLock in line with international legal frameworks."
menu:
  footer:
    name: Compliance
    weight: 50
---

_Last updated: 2025-09-19_

LeafLock is designed to help operators meet regulatory expectations across key
jurisdictions, including the European Union, United States, United Kingdom, Canada, and
Asia-Pacific regions. This overview summarises baseline controls and references additional
resources.

## General Principles
- **Transparency:** Publish privacy notices and terms that clearly explain data use,
  incident handling, and user rights.
- **Accountability:** Assign an internal point of contact for security, privacy, and
  regulatory questions. Maintain records of processing activities and vendor assessments.
- **Security by Design:** Follow secure coding practices, run automated vulnerability
  scans, and perform regular penetration testing or bug bounty programs.

## Regional Considerations
- **European Union:** Comply with GDPR (see `docs/gdpr-compliance.md`) and ePrivacy
  directives. Obtain explicit consent for non-essential cookies and marketing.
- **United States:** Align with state privacy laws (e.g., CCPA/CPRA, CPA, VCDPA), sector
  rules (HIPAA/GLBA), and export controls. Provide opt-out mechanisms where required.
- **United Kingdom:** Mirror EU obligations under UK GDPR and Data Protection Act 2018.
- **Canada:** Align with PIPEDA and provincial legislation for consent and breach
  notifications. Store data in-region when contractual obligations require it.
- **Asia-Pacific:** Review PDPA (Singapore), APP (Australia), and PIPL (China) for local
  registration, cross-border transfer, and consent requirements.

## Accessibility and Inclusion
Ensure the deployed LeafLock UI meets WCAG 2.1 AA accessibility guidelines and supports
multiple languages where required by law.

## Record Keeping and Auditing
- Enable audit logging for administrative actions and API access.
- Retain logs in accordance with legal retention schedules, segregated by environment.
- Document change management and incident response procedures.

## Incident Response
- Maintain a runbook covering detection, containment, eradication, recovery, and
  post-incident review.
- Notify affected users and regulators according to regional timelines.

## Contact
For compliance questions, email `contact@leaflock.app`.
