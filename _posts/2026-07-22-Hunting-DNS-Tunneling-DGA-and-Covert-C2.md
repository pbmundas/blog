---
title: Hunting DNS Tunneling, DGA, and Covert C2
date: 2026-07-22 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Command and Control, DNS Tunneling, DGA]
META DESCRIPTION: A hands-on guide to detecting DNS tunneling, domain generation algorithms, and covert C2 hiding inside normal-looking traffic.
---

DNS is the one protocol nobody blocks. That's exactly why it's such a popular hiding spot. Firewalls that lock down almost every outbound port will still cheerfully forward port 53 traffic to whatever resolver a host asks for, because breaking DNS breaks everything else too. Attackers know this, and DNS-based C2 has been a reliable fallback channel since long before Cobalt Strike made it fashionable.

The frustrating part of hunting this stuff is that DNS traffic is enormous. A 5,000-user network can generate millions of queries a day. Finding the handful that are actually a tunnel means you can't eyeball this  you need statistical filters that do the heavy lifting before a human ever looks at a query.

#### DGA domains have a fingerprint, even without a feed

Domain generation algorithms produce strings like xqfvbzpqol.com or k3j9dslfm2.net  pseudo-random, high entropy, and usually short-lived. You don't need a threat intel feed listing every DGA family to catch these. Shannon entropy scoring on the second-level domain name gets you most of the way there. Legitimate domains cluster in a predictable entropy range because they're made of real words, brand names, or common patterns. DGA output skews noticeably higher.

Combine entropy scoring with a consonant-to-vowel ratio check and n-gram frequency analysis (comparing the domain against a corpus of common English bigrams/trigrams) and you get a reasonably reliable classifier without needing machine learning infrastructure. Say your DNS logs show a host querying 40 unique, never-before-seen domains in an hour, all with entropy scores above 3.5 and almost no vowels  that's a strong DGA candidate worth a deeper investigation, even before you know which malware family it belongs to.

#### DNS tunneling looks different  and it's arguably worse

Tunneling isn't about generating throwaway domains for resiliency; it's about smuggling actual data through TXT, NULL, or CNAME records. Tools like iodine, dnscat2, and DNSExfiltrator encode payloads into subdomain labels and reassemble them server-side. The tell here isn't randomness in the domain itself necessarily  it's query volume and record type anomalies.

A normal workstation resolves maybe 200-400 unique domains a day, mostly A and AAAA records. A host doing DNS tunneling might send 3,000+ queries to a single parent domain in an hour, heavily weighted toward TXT record requests, with subdomain labels that are long, high-entropy, and structured (base32/base64-like padding at the end). That query-per-domain concentration is the giveaway. Real websites don't need 3,000 subdomain lookups under one parent zone in sixty minutes.

I'd also watch response sizes. Tunneling tools often push TXT record responses close to the 255-byte label limit repeatedly, whereas legitimate TXT usage (SPF records, domain verification) is a handful of queries, not a sustained stream.

#### Building the baseline before you build the alert

This is where a lot of teams get impatient and just deploy a canned Sigma rule for "high entropy DNS query" and call it done. That rule alone will drown you in false positives  CDNs, ad-tech, and legitimate SaaS platforms all generate subdomains that look randomish to a naive entropy check. Akamai edge nodes alone will trip a poorly tuned rule constantly.

The actual analysis work is building a per-environment baseline: what's the median unique-domain-per-host count, what's normal TXT query volume, which internal tools already do weird DNS things for legitimate reasons (some EDR agents do). Once you know your environment's normal, deviations become obvious instead of buried under noise.

#### Covert channels beyond DNS worth keeping on your radar

DNS gets the most attention, but the same "abuse a protocol nobody inspects closely" logic applies to ICMP tunneling, and increasingly to abusing legitimate cloud services  C2-over-Slack-API, C2-over-Google-Sheets, C2-over-Discord webhooks. These work because the destination domain is inherently trusted (who blocks discord.com?) and TLS hides the payload from casual inspection.

Hunting these requires shifting focus from "is this domain bad" to "does this process have any legitimate reason to talk to this trusted destination." A finance workstation with a PowerShell process making periodic POST requests to a Discord webhook URL has no legitimate business reason to exist, regardless of how clean Discord's reputation is.

#### Where this fits in your broader hunt program

DNS-based detection shouldn't live in isolation  it's one thread in a bigger C2 hunting fabric alongside network beaconing and process telemetry from the first post in this series. The domains rotate, the tools change, but the underlying tell  abnormal query patterns against your own environment's baseline  stays fairly constant.

If you want to practice this against real captured datasets instead of just reading entropy formulas, that's exactly the kind of lab-based hunt we run through in our DNS and covert channel modules at Threat Hunt Labs. Come run the queries yourself and see what your own traffic actually looks like.
