---
title: "Hunting Resource Development: Find Infrastructure Before It Is Used"
date: 2026-07-05 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [resource development, brand monitoring, infrastructure]
description: How to hunt for adversary infrastructure being staged and developed, catching signals of an attack before it's actually launched.
---

## What you will learn

- Monitor domains, certificates, and impersonation signals relevant to your organization.
- Enrich infrastructure before assigning priority.
- Treat external infrastructure as an early-warning lead, not automatic attribution.

By the time an attacker's infrastructure is actively communicating with a compromised host in your network, you're already hunting command-and-control, a later and more reactive stage. Resource development hunting sits earlier still  looking for signs that infrastructure is being built or acquired specifically to target your organization, sometimes visible before that infrastructure has ever touched your network at all.

## What Resource Development Actually Covers
This ATT&CK tactic encompasses everything an attacker does to prepare capability before deployment  registering domains, acquiring or compromising hosting infrastructure, developing or acquiring malware, setting up staging servers, sometimes even creating fake social media personas for social engineering campaigns. Most of this genuinely happens entirely outside your visibility, on infrastructure you have no direct access to  a real limitation worth stating plainly rather than overselling what's hunt-able here.

But a meaningful slice of resource development activity is externally observable if you know where and how to look, and that's exactly where this hunting category earns its place, distinct from purely internal telemetry-based hunting covered elsewhere in this series.

## Newly Registered Domains: A Genuinely Useful External Signal
Attackers frequently register new domains shortly before a campaign launches, often designed to closely mimic legitimate services or your own organization's actual domain, for use in phishing or command-and-control. Domain age is one of the more reliable, cheap signals available here  a domain registered within the last 30 days showing up in your inbound email or in DNS query logs is worth substantially more scrutiny than an established domain with years of legitimate history, simply because legitimate business relationships rarely spring up around brand-new domains, while attacker infrastructure frequently does.

A hunt hypothesis worth running as a standing, automated-adjacent check: flag any domain contacted by your environment (via email links, DNS queries, or web traffic) that was registered within a recent window, then apply additional scrutiny specifically to that subset rather than treating all outbound domain contact equally. Say this check surfaces a domain registered eight days ago that closely resembles your organization's actual domain with a single character substituted  that's a strong candidate for either an active or imminent phishing campaign specifically targeting your organization, and it's a finding you can act on defensively before any employee has even clicked anything.

## Monitoring for Typosquatting and Brand Impersonation
Related to newly registered domains, but worth its own hunting attention: domains that closely resemble your organization's actual brand or domain name, often used to host phishing pages or impersonate legitimate communications. Periodically checking domain registration records for close variations of your own organization's name  a hunting activity that happens almost entirely outside your own network telemetry, using external domain intelligence sources instead  can surface infrastructure being staged for a future campaign against you specifically, sometimes weeks before it's actually used.

## Certificate Transparency Logs as an Underused Source
SSL/TLS certificate issuance is publicly logged through certificate transparency systems, and this creates a genuinely useful, freely available signal: monitoring certificate transparency logs for certificates issued to domains resembling your organization's brand can surface infrastructure being prepared for a phishing or impersonation campaign, often before that infrastructure is actually deployed against any target. This is one of the more underused OSINT sources for exactly this hunting purpose  most organizations don't monitor certificate transparency logs at all, despite the data being entirely public and free to query.

## Watching for Compromised Legitimate Infrastructure
Not all attacker infrastructure is newly created  sophisticated actors frequently compromise legitimate websites or cloud services to host malicious content, since traffic to an established, reputable domain draws far less scrutiny than traffic to an obviously new one. This is harder to hunt for externally, since you're not looking for a fresh registration signal, but internally you can watch for connections from your environment to services that suddenly begin behaving unusually  a previously benign, low-traffic third-party site your organization occasionally interacts with that abruptly starts serving unexpected content types or redirecting through unfamiliar chains.

## Building These Into a Realistic Cadence
Like reconnaissance hunting, resource development hunting is well suited to periodic, lower-frequency cycles rather than continuous monitoring, with newly registered domain checks and certificate transparency monitoring being the two most practical to automate into a standing, semi-automated watch rather than a fully manual hunt run each time. The manual hunting effort is best spent on investigating the flagged candidates these automated checks surface, rather than on the raw monitoring itself.

## Why This Earliest Stage Deserves a Place in Your Program
Resource development hunting won't be the centerpiece of most programs, and it shouldn't be  the later kill chain stages still carry more hunting leverage overall. But as a lightweight, largely externally-focused layer running alongside your core hunting effort, it offers something genuinely rare: the chance to see a threat coming before it's ever touched your network, giving you time to act defensively rather than purely reactively.

## Use an infrastructure triage record

Capture the domain or certificate, discovery source, first seen, lexical similarity, registrar and hosting context, DNS history, certificate relationships, page content, affected brand or service, confidence, and next review. Escalate based on combined evidence; a newly registered lookalike domain alone is a lead.

## Key takeaway

Resource-development hunting moves visibility earlier, but external signals are ambiguous. Consistent enrichment and measured confidence turn them into useful warnings without overclaiming attribution.
