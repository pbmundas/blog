---
title: "Hunting Lateral Movement in Network Traffic"
date: 2026-08-27 12:00:00 +0530
categories: [Threat Hunting, Network Security]
tags: [Lateral Movement]
description: Attackers moving between hosts leave distinct network patterns. Here's how to hunt lateral movement using flow and protocol analysis.
---



![Lateral movement identified by correlating internal network flows and protocol behavior](/assets/img/threat-hunting/network-hunting-evidence.svg)



The gap between "attacker on one machine" and "attacker owns the domain" is almost always lateral movement, and it's one of the few attack stages that genuinely requires touching the network you can't move between hosts without generating traffic between them. That makes it one of the better-suited stages for network-based hunting specifically, as opposed to relying entirely on endpoint telemetry that an attacker with the right access might already be tampering with.



The trouble is lateral movement uses protocols that are legitimately, constantly in use for normal IT operations. SMB, RDP, WinRM, SSH none of these are inherently suspicious. The hunt is entirely about pattern and context, not protocol identity.



## Fan-out patterns are the clearest single signal available
One host connecting to a handful of other hosts over SMB or RDP across a workday is unremarkable that's an admin doing admin things. One host connecting to thirty or forty distinct internal hosts over the same protocol within a twenty-minute window is a different story entirely, and it's the single strongest lateral movement indicator in flow data by a wide margin.



Build this as a straightforward analytic: for each source host, count distinct destination hosts per protocol per rolling time window, and flag anything that spikes well past that host's own historical baseline. The baseline part matters a domain controller or a patch management server legitimately touches hundreds of hosts routinely, so a flat threshold across your whole environment produces useless noise. What you're looking for is a host that doesn't normally do this suddenly doing it. Say a developer's workstation, which historically touches two or three internal hosts a day at most, suddenly opens SMB sessions against eighteen different hosts in twelve minutes that's the kind of jump worth an immediate look, not a queued ticket for next week.



## Protocol-specific tells are worth knowing individually
SMB lateral movement, particularly via PsExec-style tooling, has a specific signature worth learning: connection to the ADMIN$ or C$ share, followed by service creation traffic, all within a tight window. Zeek or equivalent network monitoring can extract SMB tree connect events directly, and a source host connecting to administrative shares on multiple destinations in quick succession is a pattern that's rare in legitimate workflows outside of specific, known admin tooling.



RDP lateral movement is trickier because it's legitimately common, but session duration and time-of-day analysis help narrow it down. A string of RDP sessions across multiple hosts, each lasting under two minutes, is inconsistent with someone actually doing interactive work that's someone (or something automated) checking access, maybe deploying something, and moving on immediately. Compare against genuine admin RDP sessions in your environment, which tend to run considerably longer because someone's actually working inside them, and the short-duration, multi-host pattern stands out.



WMI-based lateral movement is quieter on the wire since a lot of it rides over DCOM on port 135 with dynamic high ports following, which makes port-based detection unreliable. Here, correlating with endpoint telemetry WMI process creation events alongside the network connection pattern gets you further than network data alone.



## Authentication traffic patterns reinforce what flow data suggests
If you've got visibility into Kerberos or NTLM authentication events correlated with network flow, the combination is considerably stronger than either alone. A burst of Kerberos ticket requests for service tickets against multiple hosts, timed closely with the SMB or RDP fan-out pattern from flow data, turns a "this is unusual" finding into something closer to confirmed lateral movement, because now you've got both the network-level connection pattern and the authentication evidence pointing at the same story.



This is a good example of why network hunting shouldn't run in complete isolation from your AD and Windows hunting work the strongest lateral movement detections come from correlating flow-level fan-out patterns against authentication logs, not from either data source trying to carry the finding alone.



## Time-of-day context catches what pure pattern analysis misses
A fan-out pattern that would be entirely normal during a Tuesday afternoon patch deployment window looks very different at 1 a.m. on a Saturday. Building time-of-day and day-of-week context into your lateral movement scoring not as a hard rule, but as a weighting factor helps separate a legitimate, scheduled admin operation from something happening because an attacker doesn't care what time zone your business operates in.



Cross-reference against your actual change management calendar where you can. A fan-out pattern during a documented, ticketed maintenance window gets a lower priority score. The same pattern with no corresponding change ticket, especially outside business hours, should escalate hard and fast.



## Investigating what you find, not just alerting on it
Once a fan-out pattern or protocol-specific tell fires, the investigation step is confirming source account, correlating with any available endpoint process data on the source host, and checking whether the destination hosts share anything in common same OU, same application tier, same admin group which tells you a lot about attacker intent and how far they've actually gotten versus how far they were trying to get.
