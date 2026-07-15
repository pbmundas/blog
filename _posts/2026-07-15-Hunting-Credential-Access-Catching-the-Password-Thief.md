---
title: "Hunting Credential Access: Catching the Password Thief"
date: 2026-07-15 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Credential Access]
description: A complete guide to detecting the methods attackers use to steal credentials from Windows systems, from LSASS dumping to Kerberoasting.
---



![Credential access enabling later movement toward an attacker objective](/assets/img/threat-hunting/attacker-path.svg)



Almost every serious intrusion eventually needs more credentials than the initial foothold provided, because moving laterally, escalating privileges, and reaching valuable targets all typically require access that a single compromised account doesn't have on its own. Credential access is the tactic that fuels nearly everything that follows it in a real intrusion, which makes hunting it well one of the higher-leverage investments a program can make.



## LSASS Memory Access: The Highest-Value Target on the System
The Local Security Authority Subsystem Service process holds cached credentials in memory, making it the single most valuable target for credential theft on a Windows system, and tools designed to dump credentials from memory overwhelmingly target this process specifically. A hunt hypothesis worth prioritizing above almost anything else in this category: monitor for process access events targeting LSASS (Sysmon Event ID 10, specifically watching the granted access rights requested) from processes that aren't part of a small, known, legitimate set—typically limited to specific security tooling and certain Windows internals processes.



The discrimination here is genuinely more tractable than many other hunts in this series, because legitimate reasons for an arbitrary process to request extensive read access to LSASS memory are quite rare. Consider a hunt establishes a baseline of exactly which processes legitimately access LSASS in your environment—often a remarkably short list—and then flags any access attempt from outside that list as an immediate priority finding, rather than a routine hunt output requiring extensive manual triage.



## Credential Dumping Tools and Their Behavioral Signatures
Beyond direct LSASS access, various credential dumping utilities and techniques target other storage locations—the Security Account Manager database, cached domain credentials, browser-stored credentials, and credential storage in various third-party applications. Each of these has somewhat different telemetry signatures, but they share a common pattern worth building generalized hunting logic around: unusual access to files or registry hives known to store credential material, particularly from processes or accounts that don't normally interact with those specific locations.



## Kerberoasting: Exploiting a Legitimate Protocol Feature
Kerberoasting deserves specific, dedicated attention because it exploits an entirely legitimate feature of the Kerberos authentication protocol rather than a vulnerability—any authenticated domain user can legitimately request a service ticket for any service principal name, and that ticket is encrypted with the service account's password hash, which can then be extracted and attacked offline without ever touching the target system again. This makes Kerberoasting activity itself look almost entirely legitimate at the moment it occurs, which is exactly what makes it worth hunting for specifically rather than assuming existing authentication monitoring covers it adequately.



A hunt hypothesis worth building: review Kerberos service ticket requests (Event ID 4769) for unusual patterns—a single account requesting an unusually high volume of service tickets across many different services in a short window, which is inconsistent with normal user behavior (a typical user authenticates to a handful of services they actually use, not dozens in rapid succession) and consistent with an automated tool systematically requesting tickets for offline cracking. Say a baseline shows normal accounts requesting service tickets for two or three distinct services per day on average—an account suddenly requesting tickets for forty different service principal names within an hour is a strong, specific signal worth immediate investigation.



## AS-REP Roasting: The Related, Often-Overlooked Variant
A related technique, AS-REP roasting, targets accounts that have Kerberos pre-authentication disabled, allowing an attacker to request authentication data for those accounts without needing any valid credentials at all, then attack the returned data offline. This is worth hunting for through a slightly different angle than Kerberoasting itself—since the vulnerability here is a configuration setting rather than pure behavior, a genuinely effective hunt combines behavioral monitoring for the actual AS-REP requests with a periodic administrative audit identifying which accounts in your environment have pre-authentication disabled at all, since remediating that configuration directly closes the door rather than relying purely on catching exploitation attempts after the fact.



## Credential Access via Input Capture
Beyond memory and protocol-based techniques, simpler input capture methods—keyloggers, or malicious modification of legitimate authentication prompts to harvest credentials as they're entered—remain relevant, particularly for less sophisticated but still damaging intrusions. These are harder to hunt for through log analysis alone and benefit more from EDR-level behavioral detection watching for keyboard hooking API calls or unusual modifications to system authentication dialogs, which is a good example of a credential access sub-technique better suited to strong endpoint tooling than to SIEM-based hunting.



## Prioritizing Within This Tactic Given Limited Hunting Time
Given limited hunting bandwidth, LSASS access monitoring and Kerberoasting detection consistently offer the best return on investment within this category—both target genuinely high-value, high-confidence signals with comparatively manageable false positive rates once properly baselined, compared to some of the noisier or more infrastructure-dependent techniques elsewhere in this tactic.
