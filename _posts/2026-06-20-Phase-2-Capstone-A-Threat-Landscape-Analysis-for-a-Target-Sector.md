---
title: "Phase 2 Capstone: Threat Landscape Analysis for a Target Sector"
date: 2026-06-20 12:00:00 +0530
categories: [Threat Hunting, Threat Intelligence]
tags: [capstone, threat intelligence, threat landscape]
description: A capstone exercise producing a real, professional-grade threat intelligence product that directly drives sector-specific hunt planning.
---



## Capstone outcome



![Diamond Model used to structure a sector threat landscape analysis](/assets/img/threat-hunting/diamond-model.svg)



Produce a sourced threat-landscape assessment and a prioritized hunt backlog for one clearly defined sector. Separate reported facts, analytical judgments, and assumptions throughout the document.



Reading about actor categories, kill chains, and intelligence layers separately is one thing. Producing an actual sector threat landscape analysis—the kind a real security leader would use to prioritize next quarter's hunting effort—is a different exercise entirely, and it's the one that proves whether the earlier pieces actually connected into something usable.



## Pick a Sector and Commit to It
Choose a specific industry sector—healthcare, financial services, manufacturing, whatever's relevant to your actual career direction or current employer—and build the entire analysis around it specifically, rather than staying generic. A generic threat landscape document that could apply to any organization ends up useful to none of them. Specificity forces real decisions: which actor categories from the earlier landscape piece actually target this sector meaningfully, which recent campaigns (drawing on the APT and ransomware pieces) have hit organizations in this space, and which of the intelligence layers—strategic, operational, tactical—you're drawing from for each claim.



## Structure Around the Models You've Already Learned
This capstone is the place to actually use the kill chain and Diamond Model as working tools rather than concepts you can define on request. For two or three of the most relevant threat patterns to your chosen sector, walk through where in the kill chain hunting opportunities exist specifically for that pattern—not a generic kill chain explanation, but "for ransomware affiliates targeting healthcare, here's where the actual hunting leverage sits, given what we know about how these intrusions typically unfold in this specific sector." Then take at least one specific documented incident or campaign relevant to your sector and map it across the four Diamond Model corners as a worked example, showing you can apply the model rather than just recite it.



## Ground Every Claim in a Real Source
This is where discipline matters most and where it's easiest to slip into inventing specifics for the sake of a polished-sounding document. Every claim about actor activity, campaign details, or sector targeting needs to trace back to something you can actually point to—a real vendor report, a real public incident, documented ATT&CK technique mappings. If you don't have a solid source for a specific claim, either find one, or explicitly frame it as an illustrative scenario rather than presenting it as established fact. A landscape analysis full of confidently stated but unsourced specifics is worse than one that's honest about what's well-documented versus what's a reasonable inference—the second one holds up under scrutiny from someone who actually knows the space, and the first one doesn't.



## Translate the Analysis Into an Actual Hunt Backlog
A threat landscape analysis that ends with "here's what's happening in this sector" and stops there hasn't finished the job. The deliverable needs a final section converting the analysis into three to five specific, testable hunt hypotheses that a real hunting team in this sector could pick up and run tomorrow—tied to the data sources, program model, and documentation templates from the Phase 1 capstone if you built one. Say your sector analysis concludes that healthcare organizations are seeing increased targeting of remote patient monitoring infrastructure—that observation needs to land as an actual hypothesis: "hunt for anomalous authentication patterns against remote monitoring device management interfaces, focusing on accounts with access to multiple facilities simultaneously," not just a paragraph noting the trend exists.



## Get This Reviewed by Someone Who'll Push Back
A document like this benefits enormously from a critical read by someone who'll actually challenge weak claims rather than politely nodding along. If you don't have a colleague or mentor for this, read your own draft a week after writing it, cold, and specifically hunt for any sentence that sounds authoritative but doesn't actually trace back to something concrete. That gap between "sounds right" and "is actually grounded" is exactly what separates a genuinely useful intelligence product from one that just reads like one.



## What This Capstone Actually Demonstrates
Finishing this proves something distinct from finishing the Phase 1 program design capstone. That one showed you could structure a hunting operation. This one shows you can produce the actual intelligence input that decides what that operation should be hunting for in the first place—a genuinely different and complementary skill, and one that's rarer, because it requires holding actor behavior, technical models, and sector-specific risk together in a way that most individual pieces of training never ask you to combine.



## What a credible analysis includes



Deliver an executive summary, scope and date boundary, source and confidence method, sector assets and dependencies, prioritized actor and campaign patterns, relevant techniques, key uncertainties, and five ranked hunt hypotheses. Each hypothesis must state required telemetry and why it matters to the sector.



A threat-landscape report is useful when a defender can trace every priority to evidence and every important conclusion to an action. A polished list of actors without a hunt backlog is unfinished analysis.
