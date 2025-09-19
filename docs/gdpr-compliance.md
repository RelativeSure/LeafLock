---
title: "GDPR Compliance"
slug: gdpr
summary: "Guidance for operating LeafLock in alignment with the EU GDPR."
menu:
  footer:
    name: GDPR
    weight: 20
---

_Last updated: 2025-09-19_

LeafLock is committed to safeguarding the personal data of all users and administrators.
This document outlines how the project aligns with the requirements of the EU General
Data Protection Regulation (GDPR).

## Data Processing Roles
- **Data Controller:** Deployers of the LeafLock stack determine the purpose and means of
  data processing and act as Data Controllers under GDPR.
- **Data Processor:** When LeafLock Cloud or hosted environments operate on behalf of a
  Controller, the LeafLock operations team acts as a Data Processor.

## Lawful Basis for Processing
LeafLock supports Controllers in establishing one or more lawful bases, including:
- Explicit consent captured through the user interface.
- Contractual necessity for registered accounts and service provisioning.
- Legitimate interest for security auditing, fraud prevention, and aggregated analytics.

## Data Subject Rights
LeafLock provides interfaces and APIs to assist Controllers in fulfilling requests for:
- Access, rectification, and erasure of personal data.
- Restriction of processing and objection handling.
- Data portability in machine-readable formats.

Controllers must implement organisational processes to acknowledge and resolve requests
within one month, as required by GDPR Articles 12–23.

## Data Minimisation and Retention
- Collect only data that is necessary for the stated purpose.
- Configure retention policies to purge inactive accounts and associated metadata.
- Anonymise or pseudonymise analytics where feasible.

## Security Measures
LeafLock recommends the following safeguards:
- Enforce TLS for all external connections.
- Enable role-based access controls in accordance with `docs/rbac.md`.
- Maintain audit logs for administrative actions.
- Use environment-specific secrets management and rotate credentials regularly.

## International Data Transfers
Controllers exporting data outside the European Economic Area (EEA) must ensure adequate
safeguards (e.g., Standard Contractual Clauses). LeafLock tools integrate with common
cloud vendors to support these obligations but do not replace legal due diligence.

## Breach Notification
Upon discovering a personal data breach, Controllers must notify the relevant Data
Protection Authority (DPA) without undue delay and, when feasible, within 72 hours.
LeafLock Cloud will notify Controllers immediately if a breach is detected in managed
infrastructure.

## Contact
For GDPR-related questions or Data Processing Agreements, contact `contact@leaflock.app`.
