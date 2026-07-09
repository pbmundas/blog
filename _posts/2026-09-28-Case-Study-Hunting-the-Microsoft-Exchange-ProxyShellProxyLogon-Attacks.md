---
title: Case Study: Hunting the Microsoft Exchange ProxyShell/ProxyLogon Attacks
date: 2026-09-28 12:00:00 +0530
categories: [Threat Hunting, Case Study]
tags: [Exchange]
META DESCRIPTION: How ProxyLogon and ProxyShell exploitation unfolded against Exchange servers, and what it teaches about hunting for web shell activity.
---

Within days of proof-of-concept exploit code becoming public for the ProxyLogon vulnerabilities, mass scanning and exploitation of internet-facing Exchange servers took off across the internet not one actor, but multiple groups racing to compromise as many vulnerable servers as they could before organizations patched. If SolarWinds was a lesson in patience and stealth, this pair of incidents was the opposite: speed, volume, and a race against the patch clock.

ProxyLogon (a chain of vulnerabilities including CVE-2021-26855, among others) allowed unauthenticated attackers to write arbitrary files to a vulnerable Exchange server, which in practice meant dropping a web shell and getting persistent, authenticated-feeling access without ever needing real credentials. ProxyShell, discovered a few months later, was a related but distinct exploit chain achieving a similar outcome through different vulnerable components. Both turned Exchange a system sitting on the internet edge in a huge number of organizations into a mass exploitation target almost overnight.

**Why This One Moved Faster Than Most Hunt Programs Could React**

The window between public disclosure and mass exploitation was uncomfortably short. That compresses the entire hunting timeline in a way that a slow-moving supply chain compromise doesn't. There's no leisurely "let's build a thoughtful hypothesis over the next few weeks" here if you had an internet-facing Exchange server, the relevant hunt needed to happen within days, sometimes hours, of the vulnerability details going public.

This is a genuinely different hunting posture than most programs are built for. It requires a rapid-response hunt capability a defined process for "a critical vulnerability just dropped for infrastructure we run, go hunt for exploitation evidence now" separate from the more deliberate, scheduled hunt cadence most programs default to. If your only hunting model is scheduled, hypothesis-driven investigation on a monthly cadence, you're structurally unprepared for this kind of event.

**What the Actual Hunt Hypothesis Looked Like**

The core hypothesis, once exploitation was known to be active: look for web shell artifacts dropped into Exchange's web-accessible directories, specifically unusual .aspx files in locations that shouldn't normally see new file writes particularly directories tied to the Exchange Control Panel components that the vulnerability chain targeted.

Beyond file system artifacts, process lineage told a clear story once you knew what to look for: the Exchange worker process (`w3wp.exe`) spawning unexpected child processes command shells, PowerShell, or reconnaissance tools is not normal Exchange behavior under any legitimate circumstance. That specific parent-child relationship became one of the most reliable behavioral indicators across this whole incident, and it's a pattern worth having a standing detection for regardless of whether Exchange is the specific software in question any web application server spawning a shell is worth immediate attention.

**Log Retention Became the Deciding Factor for Many Organizations**

A hard lesson from this incident: organizations with short log retention windows on their Exchange servers or worse, no centralized logging pulling those logs off the server itself struggled badly to determine after the fact whether they'd been compromised weeks earlier before they even applied the patch. Web shells can sit dormant, used sparingly, specifically to avoid drawing attention while the operator decides what to do with the access.

This ties directly back to a recurring theme in hunting generally: you can't hunt for what you didn't log, and you can't hunt far enough back if your retention window is too short. A hunt hypothesis that's technically sound but limited to seven days of available IIS logs on a system that was compromised twelve days earlier produces a false sense of clearance. Say your org's log retention on edge-facing systems is two weeks that's the actual ceiling on how far back any hunt investigating this kind of incident can meaningfully look, regardless of how good the hypothesis is.

**The Detection Engineering Takeaway That Outlasted the Specific CVEs**

The specific vulnerabilities got patched. The behavioral pattern didn't go anywhere internet-facing application servers spawning unexpected shell processes remains one of the highest-value, lowest-noise detections a SOC can maintain, applicable well beyond Exchange to any web-facing service with similar architecture. Teams that built that detection during the ProxyLogon response and kept it, rather than treating it as a one-time incident response artifact, got ongoing value from it against unrelated future exploitation attempts against other web-facing systems entirely.

The broader operational lesson: internet-facing infrastructure needs both faster patch cycles and a standing rapid-hunt capability, because the gap between disclosure and mass exploitation keeps shrinking, and a monthly hunt cadence built for slow, deliberate investigation simply isn't fast enough for this category of threat. If your team doesn't currently have a defined rapid-response hunt process separate from your regular cadence, that's a real gap worth closing before the next critical CVE drops for something sitting on your network edge. ThreatHuntLabs' incident-driven hunting modules walk through building exactly this kind of rapid-response capability, using cases like ProxyLogon as the working template.
