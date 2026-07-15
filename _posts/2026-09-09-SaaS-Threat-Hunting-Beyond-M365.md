---
title: "SaaS Threat Hunting Beyond M365"
date: 2026-09-09 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [SaaS]
description: M365 gets all the hunting attention. Here's how to extend the same discipline to Salesforce, Workday, and other business-critical SaaS.
---

## What you will learn

- Explain the attacker behavior and why it matters to the environment.
- Map the behavior to required endpoint, identity, network, or cloud evidence.
- Build a scoped hypothesis and distinguish malicious activity from legitimate administration.

A SOC that's built a mature M365 hunting program and stops there is protecting maybe half the crown jewels. Salesforce holds the entire customer relationship contracts, pricing, sales pipeline data that competitors would love to see. Workday holds every employee's salary, banking details, and social security number. Neither gets anywhere near the hunting attention Exchange and SharePoint get, mostly because the logging is less familiar and the tooling ecosystem around it is thinner.

That gap is worth closing, because the value sitting in these applications is genuinely comparable to anything in M365, and in some organizations it's higher. The good news: the hunting concepts transfer almost entirely. What changes is where the logs live and how to get at them.

## Salesforce event monitoring is the starting point, and it's often not enabled by default
Salesforce Event Monitoring or Shield Event Monitoring depending on your licensing tier captures API call activity, report exports, and login events with a level of detail that a lot of Salesforce admins never fully turn on, partly because it requires additional licensing and partly because nobody outside the security team tends to push for it. If your organization runs Salesforce for anything customer-facing and hasn't confirmed Event Monitoring is actually capturing report export and API activity, that's the first gap worth closing.

Once it's on, the highest-value hunt mirrors the S3 and SharePoint pattern from earlier posts in this series: baseline which users and integration accounts normally export which reports, and flag first-time large-volume exports, especially against reports containing customer contact data or pipeline financials. Say a sales rep who's never exported more than a few hundred records at a time suddenly pulls a report covering the entire account database thirty thousand records in one export that's exactly the pattern worth an immediate look, and it's cheap to detect once the underlying logging is actually turned on.

## API and integration account abuse deserves its own dedicated attention
Salesforce environments accumulate integration accounts over time connections to marketing automation platforms, data enrichment tools, custom internal applications and these accounts often carry broader API permissions than any individual human user would ever need, because they were provisioned once for a specific integration and never revisited. A compromised integration account credential, or an API token that leaked into a public code repository (which happens more often than most security teams would like to admit), gives an attacker programmatic access that can pull enormous volumes of data quickly without ever touching the standard login flow that most monitoring is built around.

Hunting for this means treating API-based access with the same scrutiny as interactive logins, not less unusual API call volume from a specific connected app, API access outside the hours that integration normally runs, or API calls originating from an IP range that doesn't match the known infrastructure for that integration are all worth building standing detections around.

## Workday and HR platforms need hunting focused on data sensitivity, not just access volume
Workday and similar HR platforms hold some of the most sensitive personal data an organization has, and the hunting priority here shifts slightly it's less about catching mass data exfiltration (though that matters too) and more about catching targeted access to specific individuals' records, which is a pattern that's harder to spot with pure volume-based analysis.

An HR staff member looking up an executive's compensation details outside of a documented compensation review cycle, or a manager accessing direct reports outside their own team's records, represents a different threat model than external attacker exfiltration this is where insider threat hunting and access-abuse hunting genuinely overlap, and Workday's audit logging, when properly reviewed, can surface exactly this kind of targeted, individually-scoped access that a broad export-volume rule would miss entirely because the record count per lookup is tiny.

## Single sign-on federation ties all of this back to your identity hunting work
Most mature organizations federate SaaS application access through Okta or Entra ID rather than managing separate credentials per application, which is good security practice generally and also means a huge share of SaaS-specific hunting actually starts at the identity provider level covered in earlier posts in this series. A compromised identity that's federated into Salesforce, Workday, and a dozen other SaaS applications gives an attacker access to all of them simultaneously, which is exactly why the identity provider hunting discussed for Okta and Entra ID matters as much for SaaS security as it does for M365 or infrastructure access.

Where this gets specifically SaaS-relevant: application-level session activity after a federated login is where SaaS-specific audit logs pick up the story that the identity provider's logs can't tell on their own. The identity provider confirms who logged in and when. The SaaS application's own logs tell you what they actually did once inside which is exactly the Salesforce export and Workday access-pattern hunting described above, and it only works if you're pulling both log sources together rather than treating identity provider hunting and application hunting as separate, disconnected programs.

## Building a SaaS hunting inventory before trying to hunt everything at once
The realistic starting point for most SOCs isn't "hunt every SaaS application we use" it's identifying which handful of applications actually hold data valuable enough to justify the logging and hunting investment, and starting there. A project management tool holding sprint boards probably doesn't need the same scrutiny as the CRM holding your entire customer base or the HR platform holding every employee's banking details.

Build that inventory explicitly rank your SaaS footprint by data sensitivity and business criticality, confirm what logging each one actually supports and whether it's currently enabled, and prioritize the top three or four for real hunting program investment before trying to cover everything simultaneously. Trying to boil the whole SaaS ocean at once usually just means nothing gets done well.

SaaS threat hunting is genuinely still an emerging discipline compared to how mature endpoint and network hunting have become, and that gap is exactly where a lot of real risk is currently sitting unaddressed across a lot of organizations. ThreatHuntLabs' SaaS hunting module works through building this prioritization framework and the underlying Salesforce and Workday-specific hunts against realistic scenarios a solid next step for extending hunting discipline past the applications everyone already watches.


## Build the hunt

Write one hypothesis using behavior, target, and expected evidence. Define the asset and time scope, required fields, likely benign explanations, and an escalation threshold. Test first in an authorized lab or approved dataset, then record what the available evidence can and cannot prove.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
