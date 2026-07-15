---
title: "Phase 8 Capstone - Cloud Breach Hunt Operation"
date: 2026-09-13 12:00:00 +0530
categories: [Threat Hunting]
tags: [Capstone]
description: Run a complete cloud hunt against a simulated credential-based breach the capstone that ties identity, API, and network layers together.
---

## What you will learn

- Plan and execute the capstone within a clearly authorized scope.
- Preserve the evidence, decisions, queries, and limitations needed for review.
- Turn the result into concrete detection, telemetry, or process improvements.

A single leaked access key. That's the entire starting point of a lot of real cloud breaches, and it's exactly where this capstone begins no dramatic zero-day, no sophisticated exploit chain, just a credential that shouldn't have been exposed and an attacker patient enough to actually use it well. If the earlier capstones tested whether you could work an endpoint intrusion or reconstruct a network attack from raw packets, this one tests whether you can hold together an investigation that spans identity, cloud API activity, and infrastructure simultaneously, because that's exactly what a real cloud breach demands.

This is deliberately the most complex scenario in the series, pulling together nearly everything covered across the cloud-focused posts identity provider hunting, CloudTrail-style API analysis, lateral movement through role chains, and the SaaS and container material where the scenario extends into those layers too.

## Starting from the leak, not from an alert
The scenario opens with a starting fact rather than a triggering alert: an access key was found exposed in a public code repository, and it's your job to determine whether it was actually used maliciously, and if so, how far the resulting compromise went. This inverts the usual investigative starting point instead of "here's an alert, figure out if it's real," it's "here's a confirmed exposure, figure out the blast radius," which is a genuinely different and increasingly common way real cloud investigations actually start.

The first move is establishing a timeline of when that credential was actually used, which means pulling every API call associated with it from CloudTrail (or the equivalent log source depending on which cloud the scenario is built around) across the entire period since the leak might have occurred not just recent activity, because a patient attacker might have sat on a leaked credential for weeks before using it, specifically to avoid the kind of immediate-use pattern that's easier to catch.

## Following the role assumption chain is where the real work begins
Once initial credential usage is confirmed, the investigation has to trace exactly what that access was used for and in a well-built scenario, that means following a role assumption chain similar to what's covered in the lateral movement post, where the original leaked credential's limited permissions get escalated through one or more intermediate roles to reach something considerably more valuable. Reconstructing that chain accurately, in the correct order, with each hop supported by specific log evidence rather than assumption, is exactly the skill this capstone is designed to test.

A realistic build of this scenario might have the original credential belong to a low-privilege CI/CD service account, chain into a deployment role with broader permissions, and from there reach a role capable of reading production secrets three hops, each individually explainable if you're only looking at one at a time, but only fully alarming once you've traced the whole chain and recognized where it actually terminated.

## Determining what was actually accessed, not just what access existed
Confirming the attacker had a permission isn't the same as confirming they used it, and a rigorous investigation has to distinguish between the two clearly in its findings. This capstone specifically includes both some permissions the compromised chain of access could have exploited but evidence shows weren't actually touched, and others that were genuinely used to access sensitive data. Reporting these with the same level of confidence would be a mistake, and it's one of the more subtle judgment calls the scenario is built to test.

Pulling data access events specifically S3 GetObject calls, secrets manager reads, database query logs if the scenario extends that far and correlating them precisely against the role assumption timeline established earlier is what separates a properly scoped finding from a worst-case assumption dressed up as a confirmed fact.

## Recognizing where the investigation legitimately has to stop
Cloud environments generate an enormous volume of activity, and a realistic capstone scenario includes plenty of legitimate, unrelated activity happening simultaneously with the actual intrusion other engineers deploying code, routine automation running on schedule, other service accounts doing exactly what they're supposed to be doing. Part of the exercise is correctly scoping the investigation to what's actually connected to the compromised credential's activity, rather than either missing genuine follow-on activity or, just as commonly, chasing unrelated noise because it happened to occur around the same time.

This mirrors exactly the discipline the PCAP capstone demanded around distinguishing signal from red herrings, just applied to cloud API activity instead of network packets the underlying investigative judgment being tested is the same, even though the technical surface is completely different.

## Delivering a finding that answers the question that actually matters
The deliverable here isn't a list of every API call the compromised credential made. It's a clear answer to the question that actually matters to the business: what was exposed, what wasn't, and what needs to happen next credential rotation, scope reduction on the roles involved, and specific remediation for whatever was genuinely accessed. A finding that hedges on everything because full certainty wasn't achievable everywhere isn't more rigorous, it's less useful the skill being tested includes being appropriately confident where the evidence supports it and appropriately cautious where it doesn't, and communicating that distinction clearly rather than blurring it.

Running this scenario end to end, under time pressure, with a realistic amount of noise and no roadmap handed to you upfront, is about as close as training gets to the real thing. ThreatHuntLabs' Phase 8 capstone puts you through exactly this credential-leak-to-full-scope investigation, tying together everything covered across the cloud hunting series into one operation the kind of complexity a real breach will hand you regardless of whether you've practiced for it first.


## Definition of done

Submit the scope, assumptions, data inventory, hypotheses, execution record, findings, limitations, and prioritized improvements. A reviewer should be able to reproduce the important steps and distinguish observed evidence from your interpretation.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
