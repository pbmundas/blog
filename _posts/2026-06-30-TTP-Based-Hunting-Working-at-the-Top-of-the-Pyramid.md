---
title: TTP-Based Hunting — Working at the Top of the Pyramid
date: 2026-06-30 12:00:00 +0530
categories: [Threat Hunting, Hunt Methodology]
tags: [TTP]
META DESCRIPTION: Why hunting attacker tactics, techniques, and procedures instead of artefacts produces the most durable, hardest-to-evade detections.
---

David Bianco's pyramid of pain ranks indicators by how much pain it causes an attacker when you detect and act on them — hash values sit at the bottom, trivially easy to change; TTPs sit at the top, genuinely painful to alter because doing so often means rebuilding an entire operational approach. TTP-based hunting is the practice of deliberately operating at that top tier, and it's the methodology that produces the most durable hunting value of anything covered in this series, precisely because it's the hardest for an attacker to simply route around.

**Why the Top of the Pyramid Actually Hurts Attackers**

A hash is trivial to change — recompile, repack, done. An IP address is nearly as easy — spin up new infrastructure. But a tactic, technique, and procedure represents an attacker's actual operational habits — the specific way a group typically achieves persistence, the specific tooling and command patterns they default to, the specific sequence of steps they've refined over many operations. Changing that requires genuinely rebuilding tradecraft, which is expensive, time-consuming, and something most actors — even sophisticated ones — are reluctant to do unless they're specifically forced to by repeated detection.

This is exactly why TTP-based hunting produces detections that stay relevant far longer than IOC-based ones. A hunt built around "this specific hash" is obsolete the moment the hash changes. A hunt built around "this specific sequence of process behaviors used to achieve credential access" often stays valid across dozens of that actor's operations, because the underlying technique is expensive to abandon.

**Procedures Are Where the Real Specificity Lives**

Tactics (the "why" — persistence, lateral movement) and techniques (the "how," at a general level — scheduled task creation, pass-the-hash) are useful, but procedures — the specific implementation details of how a particular actor executes a given technique — are where TTP-based hunting gets genuinely sharp. Two different actors might both use scheduled task creation for persistence (same technique), but one might consistently name tasks to mimic Windows Defender maintenance jobs while pointing to executables in AppData, and another might use entirely different naming conventions and staging locations. That procedural detail is what turns a generic technique-level hunt into something that can distinguish between actor clusters and stay durable across an individual actor's campaigns.

**Building a Procedure-Level Hunt From a Technique-Level Starting Point**

Say you're starting from ATT&CK's general documentation of a technique like scheduled task-based persistence — useful, but broad enough that a query built directly from it might return an unmanageable number of false positives, since legitimate scheduled tasks get created constantly by normal software installs and IT automation. The move that makes this hunt actually workable is narrowing from technique to procedure using whatever specific detail you have — from a CTI source, from a prior confirmed finding, or from red team exercise output — about how a specific relevant actor cluster implements this technique in practice.

If prior intelligence or a past incident indicates a relevant actor tends to name malicious tasks using patterns resembling legitimate system maintenance jobs while staging executables outside standard system directories, that specific combination — not the generic technique alone — is what your query should target. This is precisely the translation work covered in the earlier piece on turning intelligence into hypotheses, applied specifically at the procedure level rather than stopping at the more generic technique level.

**Why TTP Hunting Requires Patience Detection Can't Offer**

TTP-based hunts are almost never single-query, single-session work. Because you're hunting for a pattern of behavior rather than a discrete artifact, these hunts often require correlating multiple data sources across a longer time window — process creation, network connections, authentication events — and building a case incrementally rather than getting an immediate yes-or-no answer. This is genuinely more time-intensive than IOC-based checking, and it's worth being upfront about that cost when prioritizing hunting time, rather than pretending TTP hunting is equally cheap across the board.

**Feeding Confirmed TTP Findings Back Into Detection Engineering**

A confirmed TTP-based finding is exactly the kind of output that should convert directly into a lasting detection rule, closing the loop discussed in the hunting lifecycle piece. Because TTPs are durable and hard for attackers to abandon, a detection built from a confirmed TTP finding has genuine staying power — far more than a detection built from a confirmed IOC, which will need updating the moment the specific indicator rotates. This is a big part of why mature hunting programs, operating at HMM4 in the maturity model discussed earlier, lean so heavily on TTP-based findings specifically as the source material for their automated detection pipeline.

**Committing to the Harder, More Durable Work**

TTP-based hunting is genuinely harder than the methods lower on the pyramid — it demands more data correlation, more patience, and deeper technique-level knowledge than checking a hash or an IP against a list. But it's also where hunting produces its most lasting value, both as standalone investigation and as fuel for detection engineering that actually holds up over time.

Building the procedure-level specificity and multi-source correlation skill this method genuinely requires — not just knowing the pyramid of pain exists, but hunting at its top tier in practice — is exactly the advanced, applied work Threat Hunt Labs is built to develop, working through real TTP-based hunts against structured lab data where the durability of a finding is something you can actually see play out.
