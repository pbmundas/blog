---
title: Entra ID Threat Hunting - Identity as Perimeter
date: 2026-09-05 12:00:00 +0530
categories: [Threat Hunting, Identity]
tags: [Entra ID]
META DESCRIPTION: Master hunting identity attacks in Microsoft Entra ID sign-in anomalies, conditional access gaps, and privileged role abuse.
---

There's no firewall to breach when the entire attack surface is a username, a password, and whatever MFA factor an attacker managed to phish, bypass, or fatigue their way past. That's the reality of hunting in Entra ID, formerly Azure AD, and it's a genuinely different mental model from anything network-perimeter-based hunting prepared most analysts for. The perimeter is identity now, full stop, and Entra ID sits at the center of that perimeter for a huge share of enterprise organizations.

Hunting here means understanding not just what Entra ID logs, but what a compromised identity actually looks like moving through a tenant because the difference between a legitimate user having a bad login attempt and an attacker mid-compromise is often a matter of pattern, not any single dramatic event.

**Sign-in log anomalies are your bread and butter, but context beats raw risk scores**

Entra ID's sign-in logs carry a genuinely rich set of fields location, device compliance status, application accessed, conditional access policy outcomes, and risk detections if you've got Identity Protection licensed. The risk detections (impossible travel, anonymous IP address, unfamiliar sign-in properties) are useful signals, but leaning on them as a standalone verdict misses a lot, because sophisticated attackers increasingly route through residential proxy services specifically to defeat IP-based risk scoring.

The stronger hunt combines risk signals with behavioral context: a sign-in flagged as medium risk that's immediately followed by access to an unusually broad set of SharePoint sites, or a mailbox rule change, or a new device registration, deserves far more attention than a medium-risk sign-in that leads to nothing beyond checking email normally. Building a KQL query in Sentinel or the equivalent in whatever SIEM ingests your Entra ID logs that joins risky sign-ins against follow-on sensitive activity within a tight time window turns a noisy risk-score feed into a genuinely actionable hunting queue.

**Conditional access policy gaps are worth hunting for directly, not just assuming coverage**

A lot of organizations configure conditional access policies once, during initial tenant setup, and never revisit them as the environment grows new applications get added, new user groups get created, and coverage gaps open up quietly over time. Hunting for sign-ins that succeeded without triggering any conditional access policy evaluation at all is a worthwhile periodic exercise, because it surfaces exactly where your policy coverage has drifted from what you assume it covers.

Legacy authentication protocols are the classic gap here IMAP, POP3, and older SMTP auth methods frequently bypass modern conditional access and MFA enforcement entirely if they haven't been explicitly blocked, and they remain a favorite attacker entry point specifically because of that gap. A hunt worth running: sign-ins using legacy auth protocols, which should ideally be zero in a well-configured tenant, and any non-zero result deserves investigation into both the specific sign-in and why that protocol path was still open at all.

**Privileged role activation deserves continuous scrutiny, not just periodic access review**

If you're using Privileged Identity Management for just-in-time role activation, the activation events themselves are a genuinely high-value hunting source that a lot of teams under-review. A role activation that happens without the expected justification text, or outside a pattern consistent with that user's normal working hours, or for a role that user has never activated before, is worth a closer look regardless of whether the activation itself was technically authorized through PIM's approval workflow.

Global Administrator activations specifically deserve a standing watch this is about as close as it gets to "the keys to the tenant," and any activation of this role should be rare enough in a well-run environment that reviewing every single one isn't an unreasonable burden. Say your organization sees maybe four or five Global Admin activations a month across the whole IT team reviewing each one takes minutes and catches the rare case where an activation doesn't match any known change or ticket.

**Device registration and compliance status changes are an underused signal**

An attacker who's compromised credentials but hits an MFA wall sometimes pivots toward registering a new device to satisfy device-trust-based conditional access policies, rather than fighting through the MFA prompt directly. New device registrations from unfamiliar locations, or a compliance status flipping on a device without a corresponding legitimate management action, is a pattern worth hunting for specifically, because it represents an attacker trying to establish a persistent, trusted foothold rather than a one-off access attempt.

Correlating device registration events against the sign-in that immediately preceded them closes this loop a risky sign-in followed within minutes by a new device registration attempt is a considerably stronger finding than either event reviewed in isolation.

**Building the hunting habit around identity, not infrastructure**

The shift required here isn't really about learning new tools so much as it's about retraining the instinct. On-prem and network hunting habitually asks "what's talking to what." Entra ID hunting has to ask "who is this, really, and does what they're doing match who they've always been" instead. That's a genuinely different question, and it takes deliberate practice to build the reflex, especially for hunters who came up through network-centric backgrounds first.

Identity compromise is quietly become the dominant initial access vector in a huge share of modern intrusions, which makes Entra ID hunting less of a specialty skill and more of a core competency every hunter needs now. ThreatHuntLabs' Entra ID hunting module works through sign-in risk correlation, conditional access gap analysis, and PIM activation review against a realistic tenant with genuine identity compromise scenarios built in the kind of hands-on practice that turns "identity is the new perimeter" from a slogan into an actual working skill.
