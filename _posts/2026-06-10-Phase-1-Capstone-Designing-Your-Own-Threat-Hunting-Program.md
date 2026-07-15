---
title: "Phase 1 Capstone: Design Your Threat Hunting Program"
date: 2026-06-10 12:00:00 +0530
categories: [Threat Hunting, Threat Hunting Programs]
tags: [program building, capstone, threat hunting]
description: A capstone exercise that turns foundational threat-hunting knowledge into an operational program design.
---



## Capstone outcome



![Threat hunting operating models matched to team capacity](/assets/img/threat-hunting/program-models.svg)



Produce a program charter that another analyst could operate without relying on undocumented assumptions. This is a design exercise; do not make unapproved changes to a real production environment.



Somewhere around the point you've read about data sources, program models, hunt walk-throughs, and documentation standards separately, the honest question becomes: can you actually put all of this together into something a real organization could run? That's what a capstone is for not another concept to learn, but a forcing function to prove the earlier pieces actually connected into something usable.



## What "Designing a Program" Actually Means Here
This isn't a research paper. The deliverable is a concrete document that a security leader could hand to a new hire on day one and say "this is how we hunt here." It needs to specify a data inventory (what's collected, what's missing, what the gaps mean for hunt scope), a program model appropriate to a stated team size and maturity level, a documented hunt cadence, and templates for logging and reporting everything covered so far, synthesized into one coherent artifact rather than five separate answers to five separate prompts.



Pick a scenario before you start, even a hypothetical one, and stay consistent with it throughout. Say you're designing for a mid-size financial services company with a four-person security team, an established SIEM with 90-day retention, decent EDR coverage, but no dedicated hunting function yet. That specificity matters a program designed for "any organization" tends to stay so generic it's useless for actually running hunts, while a program grounded in one realistic scenario forces real decisions: this team can't run continuous hunting across every technique, so which two or three matter most given this industry's actual threat landscape.



## Start With Honest Constraints, Not Aspirational Ones
The single most common mistake in capstone-style program designs is writing for the enterprise-scale operation you'd like to have instead of the resourced reality you're designing for. If your scenario has a four-person team splitting hunting duties with other SOC work, don't design a tiered program with junior and senior hunter roles there's no headcount to fill those roles. Match the program model to the scenario honestly, even when the honest answer is less impressive-sounding than a fully mature HMM4 operation.



This also means being explicit about what the program will not do. A four-person team can't credibly commit to hunting continuously across all fourteen ATT&CK tactics every quarter. Naming the two or three tactics you're prioritizing say, initial access and lateral movement, given the scenario's threat profile and explicitly stating what's out of scope for now is a mark of a realistic design, not a weakness in it.



## Building the Actual Artifacts, Not Just Describing Them
A strong capstone doesn't just describe a hunt log template in prose it includes an actual template, with real fields, that could be copy-pasted into a shared drive tomorrow and used. Same for the reporting structure: don't write "reports should include the hypothesis, methodology, and outcome" as a sentence; build the actual report skeleton with those sections laid out, maybe even populated with a sample hunt using the walk-through format from earlier work, so it's clear the template actually functions rather than just sounding reasonable on paper.



This is also the right place to build a simple data source inventory table source, what it captures, retention period, known gaps grounded in your chosen scenario's stated tooling. Concrete beats comprehensive here. A ten-row table covering the sources that actually matter for your scenario's top two hunting priorities is more useful than a fifty-row table trying to catalog every conceivable log source in the abstract.



## Getting Feedback That Actually Tests the Design
Once a draft exists, the most useful thing you can do is stress-test it against a specific hypothetical: "if this program received intel about a new phishing campaign targeting this industry next Tuesday, walk through exactly how that turns into a hunt using this program's structure which data source, which template, which person (in the four-person scenario) actually runs it." If the answer requires inventing new process on the spot that isn't in your document, the design has a gap worth closing before calling it finished.



## What Finishing This Actually Proves
A completed capstone is proof to a hiring manager, to yourself, to a future team you might lead that you can hold the full shape of a hunting program in your head at once, not just execute one piece of it competently in isolation. That's a meaningfully different and more valuable skill than knowing how to run a single hunt well, and it's the skill that opens the door to leading a program rather than just staffing one.



## What your program charter must contain



Your submission should include a threat and business context, scoped mission, data inventory, operating model, quarterly cadence, hunt and report templates, escalation path, metrics, a 90-day roadmap, and an assumptions-and-gaps register. Ask a reviewer to test three questions: Can the program run with the stated people and data? Can a finding reach incident response? Can a useful hunt become a maintained detection?



A credible program design connects ambition to capacity. Its value lies in concrete ownership, repeatable artifacts, and honest constraints—not the size of its framework diagram.
