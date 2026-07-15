---
title: "Active Directory Threat Hunting Guide"
date: 2026-08-16 12:00:00 +0530
categories: [Threat Hunting, Identity]
tags: [Active Directory]
description: A working guide to hunting AD attacks Kerberoasting, DCSync, golden tickets, and the log sources that actually catch them.
---

## What you will learn

- Identify the telemetry and fields this capability can provide to a hunt.
- Use the capability to answer a bounded security question.
- Validate results safely and document coverage, blind spots, and tuning needs.

Ask any red teamer what they want on day one of an engagement and most will say the same thing: domain admin. Ask any incident responder what the worst call sounds like and it's usually "we think they have domain admin." Active Directory sits at the center of almost every serious enterprise compromise, which is exactly why it deserves its own hunting discipline rather than getting folded into generic "watch the DCs" advice.

The trouble with AD hunting is scale. A mid-sized environment generates tens of thousands of authentication events a day, and most of the interesting attacks look almost identical to normal admin behavior on the surface. The hunts that work are the ones built around the small number of things attackers genuinely cannot avoid doing.

## Kerberoasting is loud if you're listening for the right thing
Kerberoasting abuses the fact that any authenticated user can request a service ticket for any SPN-registered account, then crack the ticket offline. Event ID 4769 with encryption type `0x17` (RC4) is the textbook signal, especially when requested against service accounts that normally see maybe two or three ticket requests a day.

The part people miss is volume and pattern, not just the encryption type. A single 4769 for an RC4-encrypted ticket against a service account isn't alarming by itself plenty of legacy applications still request RC4. What matters is a single source requesting tickets for a dozen different service accounts within a few minutes, which is exactly the behavior tools like Rubeus produce when they enumerate every SPN in the domain before roasting. Baseline how many unique SPNs each user account typically requests tickets for in a week, then flag anything that blows past that baseline in an hour.

## DCSync abuse hides in plain sight because it looks like replication
DCSync lets an attacker with the right replication rights pull password hashes straight from a domain controller by impersonating another DC. The catch for defenders is that this traffic is supposed to happen between real domain controllers constantly that's how AD replication works.

Event ID 4662 with the `DS-Replication-Get-Changes-All` extended right, sourced from something that isn't a domain controller, is the detection almost every AD hunting guide points to, and for good reason it's one of the few AD detections with genuinely low false-positive potential. Where I'd push further is watching for that same right being newly granted to an account shortly before it's used. Attackers who've compromised an account with delegated AD admin rights sometimes grant themselves replication rights explicitly rather than relying on rights they already have, and that grant event (4662 again, different object) is a much earlier warning than catching the actual sync.

## Golden and silver tickets: the forgery you can't always see directly
A forged Kerberos ticket doesn't generate the same audit trail as a legitimately issued one, which is the whole point of forging it. You're not going to catch a golden ticket by looking for "ticket forgery" events, because there mostly aren't any. Instead, the hunt is about inconsistency a ticket's lifetime that doesn't match domain policy, a PAC that references a user who was disabled last month, or authentication from an account showing activity patterns wildly outside its history.

One practical technique: golden tickets forged with an old or rotated krbtgt hash still work until that hash is invalidated, so any activity from a service account that was supposedly disabled, combined with successful Kerberos auth, deserves immediate investigation rather than being dismissed as a logging glitch. This is one area where hunting genuinely beats pure detection an automated rule struggles to define "inconsistency," but an analyst reviewing a shortlist of odd auth events catches it in minutes.

## Password spraying against AD hides inside normal failure noise
Every environment has a background hum of failed logons someone fat-fingers a password, a service account's credential rotated and a script didn't get updated, whatever. Spraying attacks try to blend into that hum by keeping attempts-per-account low and spreading them across many accounts, often staying under account lockout thresholds on purpose.

The analysis that catches this isn't about volume at a single account, it's about the ratio of unique accounts to unique source IPs over a tight time window. If forty accounts each see exactly one failed logon (4625) from the same source IP inside fifteen minutes, that's not forty separate password mistakes. Building this as a stateful detection tracking distinct-account counts per source over a rolling window catches spraying that individual-event rules will never flag, because no single event looks wrong.

## Group Policy and privileged group changes deserve their own watchlist
A lot of AD hunting content stops at authentication events and misses object-level changes entirely. Additions to Domain Admins, Enterprise Admins, or any group with GPO-linking rights should generate an alert regardless of who made the change these groups shouldn't see routine membership churn, and when they do it's either a legitimate, planned change or it's an attacker consolidating access. Same logic applies to new GPOs linked to OUs containing domain controllers; that's a privilege escalation and persistence technique in one move, and it's rare enough in normal operations that the false-positive cost is low.

The common thread across all of this: AD hunting works best when you stop treating every log source as equally noisy and instead identify the small number of actions that are structurally rare for legitimate admins but structurally necessary for attackers. That's where the signal actually lives.

ThreatHuntLabs' Active Directory hunting track walks through building each of these detections against real replicated lab environments, not sanitized sample logs. If you want the muscle memory instead of just the theory, that's where to start.


## Safe lab exercise

Choose one harmless, authorized action with a known timestamp. Predict the evidence it should create, run the smallest useful query, and confirm the relevant host, identity, process, network, and time fields. Record missing fields and false-positive conditions before expanding the scope.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
