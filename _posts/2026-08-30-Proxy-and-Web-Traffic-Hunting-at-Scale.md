---
title: "Proxy and Web Traffic Hunting at Scale"
date: 2026-08-30 12:00:00 +0530
categories: [Threat Hunting, Network Security]
tags: [Proxy]
description: Millions of web requests a day hide a handful of real threats. Here's how to hunt proxy logs using categorization and anomaly detection.
---



![Proxy and web telemetry connecting destinations users volume and protocol context](/assets/img/threat-hunting/network-hunting-evidence.svg)



A mid-sized organization can generate a few million proxy log entries a day without anyone breaking a sweat. Somewhere in that pile, on a bad week, there's a C2 check-in disguised as a software update request, or a credential-harvesting page dressed up as a Microsoft 365 login. Finding it by scrolling isn't a strategy. It's how you burn an analyst's whole shift and still miss the thing that mattered.



Proxy hunting works when you stop trying to review individual requests and start treating the log as a dataset you can categorize, baseline, and score. That shift from manual review to structured analysis is really the whole discipline here.



## Categorization is the foundation, and most teams underinvest in it
Before anomaly detection means anything, you need a reasonable answer to "what kind of site is this." URL categorization sourced from a commercial feed, an open-source list, or a combination lets you separate the ninety-some percent of traffic that's routine (news sites, SaaS tools, CDNs) from the sliver worth closer inspection. Newly categorized domains, or domains with no category assigned at all, deserve more weight in your hunting than well-established, heavily categorized ones, simply because attacker infrastructure rarely has time to accumulate a reputation before it gets used and burned.



The practical hunt: filter for requests to uncategorized or freshly categorized domains, then layer in domain age from WHOIS data. A request to a domain that's both uncategorized and eleven days old is a meaningfully different finding than a request to an uncategorized domain that's been registered for six years and just never got crawled by a categorization vendor the second case is usually just an obscure legitimate site, the first deserves real attention.



## URL structure itself carries more signal than people expect
Beyond domain reputation, the actual path and query string structure of a URL tells you things. Long, high-entropy query parameters are a pattern worth watching for legitimate web applications generally use readable, structured parameters (`?user_id=4471&action=view`), while data staged for exfiltration over HTTP or C2 tasking data often shows up as a long base64 or hex-encoded blob jammed into a single parameter.



Calculating entropy on URL path and query components, similar to the subdomain entropy approach from DNS hunting, catches a category of threat that pure domain reputation checking misses entirely because the domain itself might be a compromised, otherwise-legitimate site being used as a dead drop, which means domain reputation alone tells you nothing useful. Say a marketing team's CMS gets compromised and starts hosting a small PHP webshell the domain reputation stays clean because the rest of the site is fine, but requests to a URL path like `/wp-content/uploads/2024/tmp_x9k2.php?c=<600 characters of encoded data>` stand out immediately once you're actually looking at URL structure rather than just domain trust.



## User agent strings are a cheap, high-value filter
This one's almost too easy to skip, which is exactly why it's worth mentioning directly: a meaningful share of malware and scripted attack tooling either doesn't bother setting a convincing user agent at all, or uses a default one from whatever HTTP library the tool was built with `python-requests/2.28.1`, a bare `curl` string, or a PowerShell default. Traffic showing these user agents from anything that isn't a known automation account or a documented internal tool is worth flagging on its own, and it's cheap enough to run as a standing rule with very little tuning required.



The more interesting variant is user agent inconsistency a request claiming to be Chrome 124 on Windows, but missing the TLS fingerprint characteristics real Chrome traffic would show, or requesting resources in a sequence no real browser rendering a page would produce. This requires cross-referencing against the JA3 hunting approach from TLS analysis, and combining the two catches malware that's specifically trying to impersonate legitimate browser traffic, which is a growing share of what serious campaigns actually do now.



## Volume and timing anomalies round out the picture
Requests per minute to a single destination, requests happening at machine-speed intervals rather than human browsing cadence, or web activity from a service account that should never be generating browser-style traffic at all these are the anomaly detection layer that sits on top of categorization and URL structure analysis.



A build server making outbound web requests to a domain that isn't part of any known package repository or update service is worth investigating regardless of what the URL itself looks like, because the anomaly is the source, not the destination. Baselining what each host class in your environment normally does workstations browse like humans, servers should have a tight, predictable set of destinations and flagging deviations from that baseline catches C2 traffic that's specifically designed to look boring at the individual-request level, because boring is exactly what most malware authors are going for these days.



## Turning findings into detections that scale past one analyst's shift
The point of all this categorization and scoring work is producing a shortlist small enough that a human can actually review it, ideally under fifty candidates a day even in a busy environment, rather than a raw feed of everything uncategorized or high-entropy that still numbers in the thousands. Combining multiple weak signals uncategorized domain, high URL entropy, unusual user agent, off-baseline source host into a single cumulative score, rather than alerting on any one signal independently, is what actually makes this workable at real enterprise scale.
