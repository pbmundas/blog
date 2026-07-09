---
title: CTI Fundamentals — Strategic, Operational, Tactical
date: 2026-06-14 12:00:00 +0530
categories: [Threat Hunting, Threat Intelligence]
tags: [CTI]
META DESCRIPTION: A hunter's guide to the three levels of cyber threat intelligence and exactly how each one should shape a different kind of hunt.
---

Threat intelligence gets treated as one undifferentiated blob a lot of the time — "we get CTI feeds" as if that's a complete sentence. It isn't. Strategic, operational, and tactical intelligence answer completely different questions, get consumed by completely different people, and — the part that matters most for hunters — should drive completely different kinds of hunts.

**Strategic Intelligence: The Layer Hunters Rarely See Directly**

Strategic CTI answers big-picture questions for leadership: which threat actors target our industry, what's the broader geopolitical or criminal trend affecting our risk profile, where should security investment go next year. This layer is usually consumed by CISOs and boards, not analysts running queries, and that's appropriate — a report on "ransomware targeting the healthcare sector has increased" isn't directly actionable for a specific hunt.

But it does matter for hunters in an indirect, prioritization sense. If strategic intelligence indicates your industry is seeing an uptick in a specific initial access technique, that's a legitimate input into deciding which hunting hypotheses get priority this quarter. Say a strategic report flags that manufacturing companies are increasingly targeted through exposed industrial control system interfaces — that's a signal worth feeding into your next hunt planning session, even if the report itself never mentions a specific IOC or technique you could query for directly.

**Operational Intelligence: Campaign and Actor-Level Detail**

Operational CTI sits a level down — details about specific campaigns, actor infrastructure, and TTPs tied to particular threat groups, usually consumed by SOC leads and senior analysts deciding what to actively defend against right now. This is where APT campaign reports, the kind discussed in the previous piece on Fancy Bear and Lazarus Group, mostly live. It's more actionable than strategic intelligence but still requires translation before it becomes a hunt.

A hunter reading operational intelligence needs to do the work of pulling out testable hypotheses rather than just IOCs, as covered earlier — extracting the durable technique rather than the disposable infrastructure detail. This is genuinely the layer where the most translation work happens between "intelligence received" and "hunt actually run," and it's where a lot of programs lose value, because operational reports get read, filed, and never actually converted into a tested hypothesis.

**Tactical Intelligence: IOCs, and Their Real (Limited) Value**

Tactical CTI is the most concrete and the most perishable — specific IOCs like IP addresses, file hashes, domain names tied to known-bad infrastructure. This is what most free threat intel feeds actually deliver, and it's genuinely useful for automated detection (feed these into your SIEM or EDR as watchlist entries) but has a much shorter shelf life for hunting purposes than people expect.

The honest limitation: by the time an IOC is published in a feed, sophisticated actors have often already rotated away from it. Say a hash for a known malware sample gets published — a hunt checking for that exact hash across your environment is cheap to run and worth doing, but it's checking for yesterday's specific artifact, not tomorrow's. Tactical intelligence earns its keep as a floor — a baseline check you run routinely, almost automated — not as the centerpiece of a sophisticated hunting program.

**Matching Intelligence Type to Hunt Type**

The practical skill here is recognizing which layer a piece of intelligence sits at and treating it accordingly, rather than trying to build the same kind of hunt from every input. Strategic intelligence should shape your quarterly hunt priorities, not individual queries. Operational intelligence needs deliberate translation into a testable, TTP-level hypothesis. Tactical intelligence is worth automating into routine checks, but shouldn't be mistaken for the core of your hunting program — running IOC checks and calling it a mature hunting capability is a common and understandable mistake, but it's still a mistake.

**Where Programs Actually Struggle**

Most hunting programs I've seen don't struggle with getting access to intelligence — free and paid feeds are everywhere now. They struggle with the translation layer, converting a report or feed entry into an actual hypothesis worth testing. That translation is a skill in its own right, separate from either the intelligence analysis side or the pure query-writing side, and it's usually the least explicitly taught part of the whole discipline.

Building fluency in reading intelligence at each of these three levels and knowing exactly what kind of hunt each one should produce — that's foundational work that pays off across every future hunt you'll ever run. It's a core part of what we build hands-on at Threat Hunt Labs, working through real intelligence at each layer and practicing the translation into a testable hypothesis rather than treating it as a passive reading exercise.
