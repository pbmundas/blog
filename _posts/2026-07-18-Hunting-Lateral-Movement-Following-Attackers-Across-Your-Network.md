---
title: "Hunting Lateral Movement: Following Attackers Across Your Network"
date: 2026-07-18 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Lateral Movement]
description: A complete guide to detecting the techniques attackers use to move between hosts once they're established inside your network.
---

## What you will learn

- Explain the attacker behavior and why it matters to the environment.
- Map the behavior to required endpoint, identity, network, or cloud evidence.
- Build a scoped hypothesis and distinguish malicious activity from legitimate administration.

The moment an attacker moves from one compromised host to a second one, everything about the scope and urgency of an incident changes. Lateral movement is the tactic that turns a single-host problem into a network-wide one, and hunting it well often means being the difference between an incident contained to one machine and one that requires rebuilding a domain.

## Remote Services: The Broadest, Most Foundational Category
Attackers moving laterally frequently abuse legitimate remote access protocols  RDP, SMB, WinRM  using credentials they've already harvested rather than any exploit at all. This overlaps meaningfully with the valid accounts hunting covered in the initial access piece, but the lateral movement angle asks a slightly different question: not just "is this authentication anomalous" but "does this specific host-to-host connection pattern make sense given what we know about normal traffic in this environment."

A hunt hypothesis worth building: map out normal host-to-host communication patterns for a representative slice of your environment (which hosts typically connect to which other hosts, via which protocols, and how frequently), then flag new host-to-host connections that don't fit this established pattern, particularly connections from a workstation to another workstation using protocols normally reserved for server-to-server or admin-to-server traffic. Say your baseline shows workstations essentially never establish direct RDP connections to other workstations, since legitimate remote access in your environment always routes through a small number of jump hosts  a direct workstation-to-workstation RDP connection outside that pattern is immediately suspicious, independent of whether the credentials used were technically valid.

## Pass-the-Hash and Pass-the-Ticket: Moving Without Ever Cracking a Password
These related techniques let an attacker authenticate using a captured password hash or Kerberos ticket directly, without ever needing the plaintext password at all. This connects directly to the credential access hunting covered in earlier pieces  a successful LSASS dump or ticket theft is often the direct precursor to this exact lateral movement technique. A hunt hypothesis worth building: monitor for authentication events using NTLM where the same account subsequently authenticates to multiple different hosts within an unusually short time window, which is a pattern consistent with an attacker using a single harvested hash across multiple lateral movement attempts in quick succession, rather than a legitimate user's normal, more gradual movement between the small set of systems they actually need for their job.

## Remote Service Creation as a Lateral Movement Vector
Beyond direct remote logon, attackers frequently move laterally by remotely creating and starting services on target hosts  this overlaps with the execution and privilege escalation hunting covered in earlier pieces, but specifically applied across a host boundary rather than locally. A hunt hypothesis worth building: monitor for service creation events on a target host where the creating account's session originated from a remote host rather than a local logon, particularly where the service binary path or name doesn't match your organization's known, approved remote administration tooling.

## Distributed Component Object Model Abuse
DCOM, a Windows mechanism for remote object interaction, provides another lateral movement path that's somewhat less commonly hunted than the more familiar remote services or PsExec-style techniques, making it worth specific attention precisely because it's less crowded ground, echoing the WMI persistence discussion from earlier in this series. A hunt hypothesis worth developing: monitor for DCOM-related process launches on remote hosts, particularly instances where the launched process is a scripting interpreter or an otherwise unusual choice for the DCOM object being invoked, since legitimate DCOM usage in most environments is fairly narrow and predictable once baselined.

## Building Lateral Movement Hunts Around Graph Structure, Not Just Single Connections
The most sophisticated version of lateral movement hunting treats the problem as a graph analysis exercise rather than a series of individual connection checks  building a picture of which accounts have moved across which hosts over a given time window, and looking for patterns that resemble a deliberate path through the network (account A logs into host B, then from host B, account A or a related account logs into host C, and so on) rather than isolated, unrelated events. Say a hunt builds this kind of movement graph and finds a single account touching six different hosts within a two-hour window, each connection using a different protocol, in a pattern that traces a path from a low-value workstation toward a domain controller  that graph-level pattern is far more convincing evidence of active lateral movement than any single connection in the chain would be on its own.

## Why Time Correlation Matters More Here Than Almost Anywhere Else
Lateral movement hunting benefits enormously from tight time correlation across data sources  authentication logs, process creation, network connections  precisely because the individual events involved are frequently unremarkable on their own and only become suspicious when viewed together in sequence within a compressed time window. This is a good example of where the data source mapping work covered early in this series pays dividends directly, since a hunter who's already inventoried which systems log what, and at what granularity, can actually construct this kind of tight time-correlated view rather than discovering mid-hunt that the necessary timestamps aren't precise enough to establish real sequence.


## Build the hunt

Write one hypothesis using behavior, target, and expected evidence. Define the asset and time scope, required fields, likely benign explanations, and an escalation threshold. Test first in an authorized lab or approved dataset, then record what the available evidence can and cannot prove.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
