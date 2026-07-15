---
title: "Measuring Detection Coverage From ATT&CK to Detection Gaps"
date: 2026-09-19 12:00:00 +0530
categories: [Detection Engineering]
tags: [ATT&CK]
description: A practical approach to quantifying detection coverage against ATT&CK and prioritizing which gaps actually deserve attention first.
---



![ATT&CK coverage separated into threat relevance telemetry tested detections and completed hunts](/assets/img/threat-hunting/attack-layer-workflow.svg)



Ask a CISO how good their detection coverage is and you'll usually get a number: "we cover 78% of ATT&CK." Ask what that number actually means and the conversation gets a lot quieter. Coverage percentages get thrown around in board decks like they're a settled fact, when most of the time they're a rough guess dressed up in a spreadsheet.



The problem isn't that coverage measurement is impossible. It's that most teams measure the wrong thing presence of a detection rule, rather than whether that rule actually fires against realistic technique execution. Those are very different claims, and conflating them is how organizations end up confident right up until an incident proves otherwise.



## What "Coverage" Actually Means When You Get Specific
A detection rule existing in your SIEM doesn't mean the technique is covered. It means someone wrote a rule intended to catch it. Whether it fires depends on log source availability, field parsing, threshold tuning, and a dozen other things that a checkbox on a coverage matrix doesn't capture.



Here's a concrete case. Say your matrix shows T1055 (process injection) as covered, green checkmark, done. But the underlying rule only watches for one specific injection API call pattern out of maybe six commonly used variants. You're covered against the variant someone tested two years ago and blind to the other five. On paper, 100% coverage for that technique. In practice, closer to 15%.



Real coverage measurement has to account for sub-technique granularity and, ideally, for the specific procedural variations attackers actually use not just the technique ID as an abstract category.



## Building a Coverage Model That Survives Contact With Reality
Start with ATT&CK as your skeleton, not your finish line. Map existing detections to technique and sub-technique. Then this is the part most teams skip go through and tag each mapped detection with a confidence level based on actual validation, not intent. Something like: validated (tested via atomic or purple team session within the last quarter), theoretical (written but never tested), and stale (tested once, over a year ago, environment has changed since).



You'll find that a lot of "covered" techniques drop into theoretical or stale the moment you're honest about it. That's uncomfortable in a board presentation. It's also the only version of the number that's useful for prioritization, because a stale detection is functionally closer to a gap than to real coverage.



I'd also push back on the instinct to chase 100% coverage as a goal. It's not realistic and it's not even the right target some techniques matter far more to your specific threat model than others. A regional retail company doesn't need the same investment in detecting satellite communication techniques as a defense contractor does. Coverage should be weighted against your actual threat landscape, not treated as a flat checklist where every ATT&CK cell counts equally.



## Prioritizing Gaps Without Drowning in Them
Once you've got an honest gap list, the next question is which gaps to close first, and that's where a lot of teams stall out 200 gaps on a spreadsheet is paralyzing without a scoring method.



A workable approach: score each gap on likelihood (is this technique associated with threat actors known to target your sector), impact (what's the blast radius if this specific technique succeeds undetected), and detection feasibility (do you already have the log source, or does closing this gap require a new data collection effort entirely). A gap that's high likelihood, high impact, and just needs a new detection rule against data you already collect should jump the queue ahead of a theoretically interesting but low-likelihood gap that requires onboarding an entirely new log source.



This is also where hunting and coverage measurement connect directly. A hunt into a specific gap area does double duty it might catch something live, and it generates the exact validation data you need to move that gap from "theoretical" to either "closed" or "confirmed still open."



## The Reporting Trap
One caveat, and it's worth saying plainly: coverage percentages presented to leadership without context create false confidence at the exact level where budget and risk decisions get made. A single number invites the question "why isn't this 100%" instead of the more useful conversation about which specific gaps carry real risk for this organization.



I've found it works better to present coverage as a trend with context "we closed 12 high-priority gaps this quarter, validated 40 previously-theoretical detections, and identified 8 new gaps from recent threat intel" rather than a static percentage that implies a finished state security never actually reaches.
