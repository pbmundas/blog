---
title: The Diamond Model  Giving Your Hunts Actual Structure
date: 2026-06-19 12:00:00 +0530
categories: [Threat Hunting, Threat Intelligence]
tags: [Diamond Model]
META DESCRIPTION: Applying the Diamond Model of intrusion analysis to enrich hunt hypotheses with actor, capability, infrastructure, and victim context.
---

Two hunters can look at the exact same finding  a suspicious scheduled task on one host  and walk away with completely different levels of understanding, depending on whether they stopped at "found it, confirmed malicious, closed" or kept asking questions about who's behind it, what tooling they used, and what infrastructure it connects to. The Diamond Model is essentially a structured way of forcing that second, deeper set of questions every time.

**Four Corners, One Event**

The model breaks every intrusion event into four core elements: the adversary (who's conducting the activity), the capability (the tools and techniques used), the infrastructure (the systems and network resources the adversary uses to deliver and control that capability), and the victim (who's being targeted and why). The core insight is that these four elements are always connected in any real event  you can't have a capability without infrastructure to deliver it, can't have infrastructure without a victim it's pointed at, and so on. Mapping a finding across all four corners, rather than stopping at whichever one's easiest to establish, is what turns a single data point into something genuinely useful for future hunting.

**Why Hunters Usually Stop at Capability**

Most hunt findings naturally surface the capability corner first  you found a specific malware sample, a specific technique, a specific command pattern. It's the easiest corner to establish because it's sitting right there in your own telemetry. The mistake is treating that as the finish line. Say a hunt confirms a piece of malware performing credential dumping via a known technique  that's capability, established. Pushing further into infrastructure (what command-and-control domain or IP does it communicate with) and, where possible, adversary (does this technique or infrastructure connect to any previously tracked activity, internal or from CTI) turns a single confirmed finding into something that actually informs future hunts, rather than a closed ticket that stops teaching you anything the moment it's resolved.

**Infrastructure: The Corner With the Most Reusable Value**

Of the four corners, infrastructure tends to produce the most immediately reusable hunting value, because infrastructure  C2 domains, hosting providers, SSL certificate patterns  often gets reused across multiple campaigns by the same actor cluster, even when the specific malware capability changes between operations. Say a hunt confirms a callback to a specific IP address associated with a bulletproof hosting provider known for tolerating malicious infrastructure. Even without confirming adversary attribution, that infrastructure detail  the hosting provider pattern, not just the single IP, which will rotate  is worth flagging for future hunts, because actors reusing that same hosting relationship will show up again eventually, likely with different capability but similar infrastructure fingerprints.

**Victim: The Corner That Reveals Why You, Specifically**

The victim corner gets skipped most often because it feels like the least analytically interesting piece  of course the victim is us, we're the ones running the hunt. But asking specifically why this victim, this asset, this business unit was targeted (assuming it was targeted deliberately rather than opportunistically) is genuinely useful strategic input. Say a hunt confirms an intrusion attempt against a specific research and development file share, and the victim analysis notes this is the third such attempt against R&D infrastructure specifically in six months. That pattern, visible only by deliberately examining the victim corner across multiple findings rather than treating each one in isolation, is exactly the kind of signal that should feed back into which business units get prioritized for future proactive hunting.

**Using the Model to Pivot Between Hunts, Not Just Document One**

The real power of the Diamond Model for a hunting program isn't documenting a single event thoroughly  it's using the connections between corners to pivot from one confirmed finding into the next hunt hypothesis. A confirmed capability leads you to ask about infrastructure. Confirmed infrastructure leads you to ask whether that same infrastructure shows up anywhere else in your environment, which is a hunt in itself. That infrastructure, cross-referenced against threat intelligence, might connect to a broader tracked activity cluster, which then informs what other capabilities or techniques that cluster is known to use  giving you your next hypothesis without needing any new external intelligence input at all.

**Building This Into Your Documentation Habits**

Practically, this means your hunt documentation template  the one covered in earlier pieces on documentation standards  should have room for all four corners, not just a findings summary. A finding logged with capability alone gets used once. The same finding logged across all four corners becomes a genuine reference point for connecting future findings, months later, that might otherwise look unrelated.

Learning to work the Diamond Model into real investigations  not as an academic exercise but as a genuine habit that changes how you follow up on findings  is core to the kind of structured hunting practice we build at Threat Hunt Labs, using real scenarios where pushing past the easy first answer is exactly what separates a shallow finding from a durable one.
