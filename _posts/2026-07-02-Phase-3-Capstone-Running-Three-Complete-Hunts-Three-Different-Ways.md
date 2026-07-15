---
title: "Phase 3 Capstone: Run Three Hunts, Three Different Ways"
date: 2026-07-02 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [capstone, methodology, threat hunting]
description: A capstone exercise running three full end-to-end threat hunts using intelligence-driven, behavioural, and TTP-based methodologies.
---



## Capstone outcome



![A repeatable workflow used to compare three different hunting methods](/assets/img/threat-hunting/first-hunt-workflow.svg)



Run three comparable hunts—IOC-led, behavior-based, and TTP-based—against a controlled dataset or authorized lab. Preserve the method, scope, analyst effort, findings, limitations, and improvement produced by each.



Reading about IOC-based, behavior-based, and TTP-based hunting as separate concepts is one thing. Actually running a full hunt using each methodology, start to finish, against the same environment, is what proves you understand not just what each approach is, but when and why you'd reach for one over the others. That's the point of this capstone—not more theory, but three complete demonstrations.



## Setting Up a Fair Comparison
Before running anything, pick a consistent scenario—the same hypothetical or lab environment across all three hunts—so the comparison between methodologies is actually meaningful rather than confounded by different starting conditions. Say you're working against a lab environment simulating a mid-size corporate network with standard Windows endpoints, a domain controller, and typical SIEM coverage. Keeping the environment constant across all three hunts means any difference in what each method surfaces is attributable to the methodology itself, not to different data availability between attempts.



For each of the three hunts, write the hypothesis, run the full lifecycle from the earlier piece—data validation, execution, analysis, documentation—and produce a real report, not an abbreviated summary. The goal is three genuinely complete artifacts you could show a hiring manager as evidence you can execute each approach competently, not three rough sketches.



## Hunt One: IOC-Driven, With Genuine Pivoting
Start with a hunt seeded from a specific indicator—a hash, domain, or IP tied to a documented campaign relevant to your chosen scenario. The easy, shallow version of this hunt stops at a match-or-no-match result. Don't let this one stop there. Whatever the initial result, push into the pivoting behavior covered in the earlier piece on IOC hunting—if there's a match, follow it into surrounding process and network behavior; if there's no match, document specifically what was checked and why you're confident the absence is meaningful rather than just a gap in coverage.



This hunt should demonstrate you understand IOC hunting's actual value: not the indicator itself, but what you do with it once you've got a hit or a confirmed clean result.



## Hunt Two: Behavior-Based, With a Real Baseline
The second hunt should start from a baseline you actually build, not assume. Pick a specific behavior category—authentication patterns for a defined set of accounts, or process execution patterns for a specific host role—and document what "normal" looks like using whatever historical data your scenario provides, before hunting for deviation from it. This is the hardest of the three to execute convincingly without real baseline-building discipline, and that difficulty is exactly the point—it forces you to practice the patient, unglamorous groundwork this method genuinely requires rather than skipping straight to the anomaly-spotting part.



Document the chains-not-single-anomalies reasoning from the behavior-based piece explicitly here—show that any candidate finding you flag is being evaluated as part of a combination of factors, not a single deviation treated in isolation.



## Hunt Three: TTP-Based, With Procedure-Level Specificity
The third hunt should demonstrate the highest level of the pyramid of pain—start from a documented technique, narrow it to procedure-level specificity using whatever detail your scenario's threat intelligence provides, and build a hunt that correlates multiple data sources over a longer time window rather than relying on a single query's result. This hunt should take noticeably longer to execute than the other two, and that's expected—TTP-based hunting genuinely is more time-intensive, and the capstone should reflect that honestly rather than compressing it artificially to match the pace of the simpler hunts.



## Comparing the Three Honestly
Once all three are complete, write a short comparative reflection: which methodology was fastest to execute, which produced the most durable finding (one likely to stay relevant even if specific indicators or infrastructure change), and which required the most domain-specific environmental knowledge to run well. Be honest if one methodology genuinely didn't surface anything interesting in your particular scenario—a clean result isn't a failed hunt, as covered in the lifecycle piece, and reporting that honestly is itself a demonstration of good hunting discipline rather than something to paper over.



## What Completing This Actually Demonstrates
A completed three-hunt capstone shows you can move fluidly between methodologies based on what a situation calls for, rather than defaulting to whichever one you happen to be most comfortable with. That flexibility—knowing which tool fits which problem—is a meaningfully more advanced skill than mastering any single methodology alone, and it's exactly the kind of comparative, hands-on practice that separates someone who's read about hunting from someone who can actually run a program.



## What to submit



Submit three hunt records plus a comparison table covering data requirements, preparation time, execution time, candidate volume, false-positive burden, confidence, reusable logic, and limitations. Explain which method best fit each question and identify one detection or telemetry improvement from every hunt.



There is no universally best hunting method. The capstone demonstrates judgment: choosing a method whose strengths match the question, evidence, and available time.
