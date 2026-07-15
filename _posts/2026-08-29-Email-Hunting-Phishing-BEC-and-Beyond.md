---
title: "Email Hunting - Phishing, BEC, and Beyond"
date: 2026-08-29 12:00:00 +0530
categories: [Threat Hunting]
tags: [Email Security]
description: Email is still the top initial access vector. Here's how to hunt phishing and BEC using gateway and endpoint telemetry together.
---

## What you will learn

- Explain the concept in operational threat-hunting terms.
- Connect it to a decision, data requirement, or repeatable workflow.
- Apply it through a small exercise and document the limits of the result.

Every phishing awareness campaign in the world hasn't made email stop being the most common way attackers get their first foothold, and it isn't going to. People open attachments, click links, and wire money because email is designed to feel urgent and personal, and attackers have gotten very good at exploiting exactly that design. Hunting email threats means accepting upfront that prevention alone will never close this gap completely, and building an investigative capability around the assumption that some of it gets through.

The good news is email generates a lot of telemetry, both at the gateway and once a message actually lands on an endpoint, and combining those two views catches a lot that either one alone would miss.

## Header analysis still catches more than people expect
Email headers carry a surprising amount of forensic detail that most gateway products summarize away into a simple pass/fail spam score, throwing out information that's genuinely useful for hunting. SPF, DKIM, and DMARC results matter, obviously, but the more interesting hunt is in the Received header chain and the Reply-To field mismatch pattern that's a hallmark of business email compromise specifically.

A message displaying as coming from your CFO, passing SPF because it was sent through a legitimately configured but attacker-controlled domain that's a single character off from your real one, with a Reply-To address that doesn't match the From address at all that's a pattern worth building a standing detection around rather than relying on the recipient to notice the visual difference between a lowercase L and a capital I in a domain name at a glance. Pulling Reply-To/From mismatches specifically, cross-referenced against your organization's executive names appearing in the display name field, is one of the higher-value narrow detections available for catching BEC attempts targeting your leadership specifically.

## Attachment and link analysis needs to happen before and after delivery
Gateway-level sandboxing catches a meaningful share of malicious attachments, but it's not perfect time-delayed payloads, geofenced malware that only detonates for specific IP ranges, and links that resolve to benign content at scan time but get weaponized hours later all slip through sandboxes designed around immediate detonation. This is exactly why "delivered clean" can't be the end of your investigative interest in a message.

Re-scanning previously delivered URLs periodically even a simple daily re-check against threat intel feeds for links that were clean at delivery time catches the delayed-weaponization pattern that a lot of phishing campaigns rely on specifically to slip past initial gateway scanning. If you've got the retention for it, keeping a log of every URL delivered to inboxes, independent of whether it was flagged, gives you something to retroactively hunt against once new threat intelligence comes in about a campaign you didn't catch in real time.

## Endpoint telemetry closes the loop gateway data can't
The gateway tells you what arrived. It doesn't reliably tell you what happened after someone clicked, and that gap is where a lot of the real investigative work lives. Correlating email delivery timestamps against subsequent process creation events on the recipient's endpoint did Outlook or the browser spawn a child process shortly after the message landed, did a macro-enabled document execution follow within minutes of the attachment being opened turns a "we don't know if anyone clicked" gateway alert into a concrete, scoped investigation.

This correlation is exactly where the malware analysis and endpoint hunting skills from earlier posts feed directly into email investigation. A phishing email with a malicious attachment isn't really an "email security" problem in isolation it's an initial access event that needs the same process tree analysis, persistence checking, and network correlation you'd apply to any other endpoint compromise, just triggered by a different entry point than usual.

## BEC hunting is mostly about behavioral baseline, not malware detection
Business email compromise attacks frequently involve no malware at all no attachment, no malicious link, just a well-crafted message asking for a wire transfer or a change to payroll banking details. Traditional email security tooling, built around scanning content and attachments, genuinely struggles against this because there's nothing technically malicious in the message to detect.

The hunt here shifts toward behavioral and contextual analysis: is this the first time this "vendor" has requested a change to payment details, does the urgency language match patterns seen in confirmed BEC cases (tight deadlines, requests to bypass normal verification, insistence on email-only communication), and critically, does the actual email address match the vendor's known-good address history rather than just displaying a familiar name. Building a running log of vendor payment detail changes and flagging any change request that arrives via email without a corresponding verified phone confirmation is a process control as much as a technical hunt, but it's the control that actually stops most BEC losses in practice the technical detection piece mostly supports the investigation after the fact rather than preventing the attempt in the first place.

## Treating email as a starting point, not an isolated case file
The single biggest improvement most SOCs could make to email threat hunting isn't a new tool it's stopping the habit of closing an email security case the moment the malicious message gets removed from inboxes. If someone clicked before the message was pulled, that's an endpoint investigation now, and it needs the same rigor as any other initial access finding, tracked through to confirm whether anything downstream actually happened.

Email will keep being the front door attackers prefer, mostly because it works often enough to keep being worth the effort. ThreatHuntLabs' email hunting module covers building header analysis, delayed-detonation re-scanning, and gateway-to-endpoint correlation workflows using real phishing and BEC samples solid grounding for turning "we removed the email" into "we confirmed nothing happened after it landed."


## Apply the lesson

Choose one real or lab scenario and write down the decision this concept should improve, the evidence required, the owner, and the expected output. Review the result with someone who did not perform the work; revise any assumption they cannot trace to evidence.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
