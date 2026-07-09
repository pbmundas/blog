---
title: Building a Complete ATT&CK Hunt Playbook
date: 2026-07-25 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Playbook]
META DESCRIPTION: A practical walkthrough for mapping a full hunt playbook across all 14 MITRE ATT&CK tactics, from recon to impact.
---

Most hunt programs end up lopsided. Teams get good at one or two tactics — usually C2 and initial access, because that's where the tooling and blog posts concentrate — and leave big gaps everywhere else. I've seen mature SOCs with excellent phishing detection and beaconing analytics that have almost nothing built for Discovery or Collection, simply because those tactics don't generate the same volume of vendor content and conference talks.

A real hunt playbook needs to cover the whole kill chain, not just the flashy parts. Fourteen tactics, start to finish, each with at least one testable hypothesis and a data source mapped to it. That's the capstone exercise worth actually doing, not just reading about.

#### Start with what data you actually have, not what you wish you had

Before mapping a single technique, inventory your log sources honestly. Do you have process creation events with command-line logging (Sysmon Event ID 1, Windows Event ID 4688 with command-line auditing enabled)? Full DNS logs? Cloud API audit trails? Network flow data? A playbook built around techniques you can't actually detect with your current telemetry is a wish list, not a playbook.

Say your organization has solid EDR coverage on endpoints but only NetFlow (no full packet capture or DNS logs) at the network layer. That immediately tells you your Command and Control and Exfiltration coverage will lean heavier on process-to-network correlation than on payload inspection — which changes which specific techniques within those tactics you can realistically hunt for versus which ones you should flag as a coverage gap to address later.

#### Map tactics to techniques to actual queries — don't stop at the framework level

It's easy to produce a nice-looking spreadsheet that says "Persistence: covered" with a checkmark. That's not a playbook, that's decoration. Real coverage means, for each tactic, picking the specific sub-techniques most relevant to your environment and threat model, writing an actual hypothesis ("if an attacker established persistence via scheduled task, I'd expect a new task registered outside our standard deployment windows, likely running from a non-standard binary path"), and having a query or detection rule that tests it against real data.

For Persistence alone, you might reasonably cover: scheduled task creation (T1053.005), new service creation (T1543.003), registry Run key modification (T1547.001), and WMI event subscription (T1546.003) — four separate hunts, each with its own data source and query, not one generic "persistence" bucket.

#### The tactics everyone forgets

Discovery, Collection, and Lateral Movement consistently get the thinnest coverage in playbooks I've reviewed. Discovery techniques — net.exe enumeration, nltest domain trust queries, PowerShell reconnaissance cmdlets — generate a ton of legitimate noise from IT admins doing their actual jobs, which makes people give up on tuning detections for it. But the volume and sequencing matters: a workstation running whoami, net group "domain admins" /domain, and nltest /domain_trusts within ninety seconds of each other is a very different story than an admin running one of those commands once a week.

Collection is similarly underbuilt because it often looks identical to normal file access until you correlate it with everything else — a user account suddenly opening and reading two hundred documents across shares it's never touched before is a Collection signal worth its own hunt hypothesis, separate from your exfiltration monitoring, even though the two tactics obviously feed into each other.

#### Tying tactics together into attack-path hunts, not isolated checkboxes

The most valuable playbooks I've built don't treat these fourteen tactics as independent silos — they chain hypotheses together into attack-path narratives. Initial access via phishing, followed by Discovery commands within the hour, followed by lateral movement over SMB admin shares, followed by Collection against finance shares, followed by staging and exfiltration — that's one coherent hunt built from five tactic-level hypotheses stitched together, and it catches intrusions that no single-tactic query would flag on its own because each individual step looks borderline-normal in isolation.

This is really the difference between a checklist and an actual hunt program: the checklist proves you thought about all fourteen tactics; the attack-path version proves your detections would actually catch a real intrusion moving through your environment end to end.

#### Making the playbook a living document, not a one-time project

ATT&CK itself keeps growing — new sub-techniques get added, existing ones get refined — and your environment changes too: new cloud services, new remote access tools, new business units with different normal baselines. A playbook built once and left untouched for a year drifts out of relevance fast. Build a review cadence into it, quarterly at minimum, where you revisit coverage gaps and retire hunts against techniques that are no longer relevant to your actual attack surface.

Building a genuinely complete playbook — one that covers all fourteen tactics with real queries against real data, not just a mapped spreadsheet — is exactly the capstone project we walk through step by step in our full hunting track at Threat Hunt Labs. If you've made it through this whole series, that's the natural next step: come build your own complete playbook with us instead of leaving it as a someday project.
