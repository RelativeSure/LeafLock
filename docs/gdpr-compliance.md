---
title: "GDPR Compliance"
slug: gdpr
summary: "Your rights under GDPR and how LeafLock protects your personal data."
weight: 20
type: "page"
layout: "single"
toc: true
categories:
  - "Legal"
  - "Privacy"
tags:
  - "gdpr"
  - "privacy"
  - "data-protection"
  - "user-rights"
menu:
  footer:
    name: "GDPR"
    weight: 20
  main:
    name: "GDPR Compliance"
    weight: 20
    parent: "legal"
---

_Last updated: 2025-09-19_

## Privacy First: Zero-Knowledge Protection

**LeafLock is fundamentally different from most online services.** We've built our application with zero-knowledge architecture, which means **we cannot read your notes even if we wanted to**. Your data is encrypted on your device before it ever reaches our servers, and only you have the keys.

This unique approach means that many traditional data protection concerns simply don't apply to LeafLock - because we never see your sensitive information in the first place.

## What This Means for You

✅ **Your notes are completely private** - We cannot access, read, or analyze your note content
✅ **No data mining** - We can't build profiles or sell your information because we don't have it
✅ **Breach protection** - Even if our servers were compromised, your notes remain encrypted
✅ **Government requests** - We literally cannot hand over your note content to anyone

## Your GDPR Rights

As a LeafLock user in the EU, you have the following rights:

### 🔍 Right to Know What Data We Have
**What this means:** You can ask us what personal information we've collected about you.
**At LeafLock:** We only have your email address, account metadata, and usage logs. Your actual notes? We can't access them, so we can't tell you what's in them (because we don't know).

### 📋 Right to Access Your Data
**What this means:** You can get a copy of all your personal data.
**At LeafLock:** We can provide your account information and usage patterns, but your notes are encrypted with your keys, so only you can decrypt them.

### ✏️ Right to Correct Information
**What this means:** You can ask us to fix any wrong information.
**At LeafLock:** You can update your email address through your account settings. Since we don't see your note content, there's nothing there for us to correct.

### 🗑️ Right to Be Forgotten
**What this means:** You can ask us to delete your personal data.
**At LeafLock:** Simply delete your account, and we'll remove all your data within 30 days. This includes your encrypted notes (which we couldn't read anyway).

### ⏸️ Right to Limit Processing
**What this means:** You can ask us to stop using your data in certain ways.
**At LeafLock:** Contact us if you want to temporarily suspend your account while keeping your data.

### 📦 Right to Data Portability
**What this means:** You can get your data in a format to move to another service.
**At LeafLock:** You can export your notes anytime from within the app. Since they're encrypted locally, you have full control over your data.

### 🚫 Right to Object
**What this means:** You can object to how we process your data.
**At LeafLock:** We don't do marketing or profiling since we can't see your content. You can object to our minimal usage analytics if needed.

## What Data We Actually Collect

Unlike most online services, LeafLock collects very little data because of our zero-knowledge design:

### 📧 Account Data (Required)
- **Email address**: For login and account recovery
- **Encrypted password hash**: We never see your actual password
- **Account creation date**: For service administration

### 📊 Minimal Usage Data (For Service Operation)
- **Login times**: To detect suspicious activity
- **Feature usage patterns**: To improve the app (but not what you write)
- **Error logs**: To fix bugs and keep the service running

### 💬 Support Communications (If You Contact Us)
- **Support messages**: Only what you choose to share with us
- **Feedback**: If you provide it voluntarily

### 🚫 What We DON'T Collect
- **Note content**: Encrypted on your device, we can't read it
- **Note titles**: Also encrypted with your keys
- **Search queries**: Happen locally on your device
- **Personal profiling data**: We can't build profiles from encrypted data
- **Marketing data**: We don't track you across websites
- **Analytics beyond basic usage**: No detailed behavioral tracking

## Legal Basis for Processing

We process your limited data based on:
- **Contract performance**: To provide the LeafLock service you signed up for
- **Legitimate interest**: Basic security monitoring and service improvement
- **Consent**: For optional analytics (which you can opt out of)

## Exercising Your Rights

### 📧 How to Contact Us
Email us at `contact@leaflock.app` with:
- Your account email address
- What you want to do (delete account, get data copy, etc.)
- Any additional details to help us verify it's really you

### ⏰ Response Time
We'll get back to you within **30 days**. Most requests are much faster since we don't have much data to process.

### 💰 Always Free
Exercising your privacy rights is always free. We won't charge you for deleting your account, providing your data, or correcting information.

## Frequently Asked Questions

### ❓ "Can you really not see my notes?"
**No, we genuinely cannot.** Your notes are encrypted with keys that only exist on your devices. Even our engineers with full server access cannot decrypt your content.

### ❓ "What if I lose my password?"
Unfortunately, if you lose your password, we cannot recover your notes because we don't have the encryption keys. This is the trade-off for true privacy.

### ❓ "Do you share data with third parties?"
We don't share your data with advertisers, data brokers, or analytics companies. The only exception would be if legally required (but remember, we can't share your note content because we can't access it).

### ❓ "How do I know you're not lying about encryption?"
Our code is open source on GitHub. Security researchers can audit our encryption implementation to verify our claims.

### ❓ "What happens to my data if LeafLock shuts down?"
You can export all your notes anytime since they're encrypted locally. If we ever shut down, we'd give users advance notice to export their data.

## Technical Security Details

### 🔐 Encryption Specifications
- **Note content**: XChaCha20-Poly1305 encryption (military-grade)
- **Passwords**: Argon2id hashing with high memory requirements
- **Data in transit**: TLS 1.3 encryption for all connections
- **Server encryption**: Additional server-side encryption for metadata

### 🛡️ Security Practices
- **Regular security audits**: Automated vulnerability scanning
- **Minimal access**: Strict limitations on who can access any data
- **No backdoors**: We've designed the system so even we can't bypass encryption
- **Open source**: Code is publicly auditable for transparency

## Data Retention

We keep data only as long as necessary:
- **Your notes**: Until you delete them (but we can't read them anyway)
- **Account info**: Until you delete your account
- **Usage logs**: 12 months maximum (for security monitoring)
- **Support messages**: 3 years (for quality purposes)
- **Deleted accounts**: Completely removed within 30 days

## International Data Protection

If your data crosses borders, it's still protected:
- **EU adequacy**: We only use data centers in countries approved by the EU
- **Standard contracts**: Legal agreements ensuring GDPR-level protection everywhere
- **Encryption advantage**: Since your notes are encrypted, location matters less

## Data Breach Response

If something bad happens:
- **72-hour notification**: We'll tell authorities within 72 hours if required
- **User notification**: We'll contact you immediately if your data might be at risk
- **Transparency**: We'll explain exactly what happened and what we're doing about it
- **Encryption protection**: Remember, even in a breach, your notes stay encrypted

## Contact Information

- **Privacy questions**: `contact@leaflock.app`
- **Data requests**: `contact@leaflock.app`
- **Security concerns**: `contact@leaflock.app`

We're a small team committed to your privacy. You'll hear back from real humans, not automated responses.
