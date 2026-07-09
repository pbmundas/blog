---
title: The Threat Hunting Maturity Model Explained
date: 2026-06-03 12:00:00 +0530
categories: [Threat Hunting, Introduction]
tags: [Threat Hunting, Beginning]
META DESCRIPTION: A walkthrough of the five levels of threat hunting maturity, what separates them, and how to honestly assess where your program stands.
---

Every SOC leader claims their team "does threat hunting." Ask a follow-up question — how many hunts last quarter, what hypotheses drove them, what got automated afterward — and the confident answer usually falls apart within about thirty seconds. That gap between claimed maturity and actual maturity is exactly what the hunting maturity model was built to expose.

The model, originally popularized by David Bianco and widely adopted since, breaks hunting capability into five levels: HMM0 through HMM4. It's not about tooling budget. A team with an expensive SIEM and no hunting discipline can sit at HMM1, while a smaller team with sharper analysts and better data hygiene can sit at HMM3. Maturity here is about process and data, not license spend.

**HMM0 — Initial: Running on Alerts Alone**

At this level, there's no hunting happening at all, even if the org thinks there is. The SOC relies entirely on automated alerting — SIEM correlation rules, EDR alerts, vendor signatures — and analyst time goes entirely into triaging what those tools surface. Nobody's proactively going looking for anything. This isn't a criticism of the analysts; it's usually a resourcing reality. If your entire team is at 90% capacity just triaging the alert queue, there's no bandwidth left for hunting, no matter how skilled anyone is.

The tell for HMM0 is simple: if every single finding in the last quarter started with an automated alert, you're here, regardless of what the org calls itself.

**HMM1 — Minimal: Borrowing Other People's Intel**

This is where most orgs land when they first attempt hunting seriously. Hunts happen, but they're driven almost entirely by external threat intelligence — IOC lists from a vendor feed, a new CVE advisory, a report about a specific campaign. The hunter checks whether known-bad indicators from that intel show up anywhere in the environment.

It's a legitimate first step and genuinely catches things — IOC-driven hunts have found real compromises plenty of times. The limitation is that you're only ever hunting for what someone else already discovered. If an attacker's techniques haven't made it into a public report yet, HMM1 hunting won't surface them. You're perpetually a step behind, hunting for yesterday's known threats rather than today's unknowns.

**HMM2 — Procedural: Following Other Analysts' Playbooks**

At HMM2, the org starts running hunts based on procedures developed elsewhere — published hunting playbooks, TTP-based hunt guides tied to MITRE ATT&CK techniques, methodology someone else wrote up and shared. A hunter might run through a documented procedure for detecting Kerberoasting, following steps someone else validated, adapting them slightly to local log sources.

This is a real step up because you're now hunting for techniques, not just indicators — techniques don't change as fast as IOCs do, so the hunts stay relevant longer. The ceiling here is that the org still isn't generating its own hunting hypotheses. Every hunt traces back to someone else's playbook. Say a team runs through 15 published ATT&CK-based hunt procedures over a quarter — solid coverage, but entirely reactive to what's already been documented publicly, not what's specific to this environment's actual risk profile.

**HMM3 — Innovative: Building Your Own Hypotheses**

This is where hunting starts to feel like the discipline it's meant to be. Analysts generate their own hypotheses based on their specific environment, their own knowledge of what's unusual for this network, and their own read of emerging threats — not just following someone else's published procedure. A hunter here might notice that a specific business unit has an unusual pattern of after-hours VPN logins and build a hypothesis around it without any external report prompting the idea.

Data quality becomes the real bottleneck at HMM3, not creativity. You need enough visibility across endpoints, network, identity, and cloud to actually test a novel hypothesis — a great idea for a hunt that dies because the relevant logs were never collected is a constant frustration at this level. Teams here typically start building out dedicated data lakes or expanding SIEM retention specifically to support hunting, separate from whatever retention compliance already required.

**HMM4 — Leading: Automating What Works and Hunting What's Left**

At the top level, successful hunt procedures get automated into standing detections, freeing hunters to move on to genuinely novel territory instead of re-running the same manual hunt every month. This is the feedback loop mentioned earlier, running at full speed: a hunt confirms a technique is a real risk, that hunt logic gets converted into an automated detection, and the human hunters move to the next open question.

Very few orgs actually operate at HMM4 consistently. It requires detection engineering and hunting to be tightly coupled — not separate teams that occasionally talk — plus mature data infrastructure and enough hunting volume that automation of successful hunts is worth the engineering investment. Most orgs that claim HMM4 are actually running a mix of HMM2 and HMM3 with a handful of automated hunts scattered in.

**Assessing Your Own Level Honestly**

Most self-assessments run one to two levels higher than reality, mostly because "we did a hunt once based on a hypothesis" gets counted as HMM3 maturity even if it was a single event rather than a sustained practice. A more honest test: look at your last ten findings. Trace each one back to its origin — alert, external intel, published playbook, internal hypothesis, or automated-from-a-prior-hunt. Whichever category dominates is your actual level, not the one on the slide deck.

Climbing this ladder isn't really about tooling purchases. It's about building the muscle to generate original hypotheses and the data discipline to test them — which is exactly the kind of hands-on practice we focus on at Threat Hunt Labs, working through real hypothesis generation rather than just running someone else's playbook.
