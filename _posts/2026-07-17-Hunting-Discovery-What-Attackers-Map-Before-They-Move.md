---
title: Hunting Discovery — What Attackers Map Before They Move
date: 2026-07-17 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Discovery]
META DESCRIPTION: Detecting the reconnaissance and enumeration techniques attackers use after initial access, before deciding where to move next.
---

Once an attacker has a foothold, they almost never know your environment well enough yet to move confidently. Discovery is the tactic covering everything they do to fix that — mapping accounts, systems, shares, and trust relationships before committing to a specific lateral movement or escalation path. It's a tactic that generates real telemetry, and it's one of the more underrated early-warning opportunities in the entire kill chain.

**Why Discovery Almost Always Happens, Even for Skilled Attackers**

Unlike some tactics that a sufficiently prepared attacker with prior intelligence might skip entirely, discovery is genuinely difficult to avoid altogether, because even the most well-prepared attacker rarely has perfect prior knowledge of a specific target environment's internal structure. This makes discovery hunting unusually reliable compared to some other tactics — you're not hunting for something an attacker might optionally do, you're hunting for something almost every real intrusion has to do at some point, which shifts the odds meaningfully in the hunter's favor.

**Account and Group Enumeration: The Most Common Starting Point**

Attackers typically start by mapping the account and privilege landscape — which accounts exist, which groups they belong to, and critically, which accounts hold privileged access like domain admin membership. Native tools like `net user`, `net group`, and various PowerShell Active Directory cmdlets accomplish this, and while these are legitimately used by IT staff constantly, the volume and pattern of use differs meaningfully between routine administration and active reconnaissance.

A hunt hypothesis worth building: monitor for a high volume of enumeration commands executed in rapid succession from a single host or account, particularly enumeration targeting privileged groups specifically (domain admins, enterprise admins) rather than routine, narrow lookups an IT helpdesk technician might perform for a single user's ticket. Say a normal help desk interaction involves looking up one or two specific user accounts to resolve a ticket — a session that instead enumerates the full membership of every privileged group in the domain within a few minutes is a meaningfully different, much more suspicious pattern.

**Network and Share Discovery**

Beyond accounts, attackers map the network itself — which hosts are reachable, which file shares exist and what they contain, which systems are running specific services worth targeting. Tools and techniques here range from simple native commands (`net view`, checking for accessible shares across the network) to more sophisticated network scanning. A hunt hypothesis worth running: review for unusual patterns of SMB share enumeration originating from a single host, particularly enumeration touching an unusually broad range of other hosts in a short window, which is inconsistent with how legitimate users typically interact with file shares (usually a small, consistent set of shares relevant to their specific role) and consistent with an attacker systematically mapping what's available.

**Domain Trust and Active Directory Structure Discovery**

More sophisticated attackers, particularly those planning significant lateral movement across a complex environment, often enumerate domain trust relationships and broader Active Directory structure — organizational units, group policy configuration, and trust relationships between domains or forests. This level of discovery tends to correlate with more capable, patient actors, since less sophisticated intrusions often don't bother mapping this deeply before moving. A hunt hypothesis worth building for organizations with complex, multi-domain environments: monitor for enumeration queries targeting domain trust configuration or cross-domain group policy objects, since legitimate use of these specific queries tends to be limited to a small, identifiable set of IT and security administration accounts.

**Process and Software Discovery: Understanding What's Actually Running**

Attackers also frequently enumerate running processes and installed software on compromised hosts, partly to understand what security tooling they're up against and partly to identify additional software worth exploiting or abusing for further access. A hunt hypothesis worth building: monitor for systematic enumeration of running processes or installed software inventories occurring outside the context of legitimate IT asset management tooling, particularly correlated with other suspicious activity on the same host in the surrounding time window.

**Cloud Environment Discovery: A Newer, Increasingly Relevant Category**

For organizations with meaningful cloud infrastructure, discovery increasingly extends into cloud-specific enumeration — mapping IAM roles and permissions, enumerating storage buckets or databases, checking for misconfigured resources with overly permissive access. This requires cloud provider audit logs (CloudTrail, Azure Activity Logs) rather than traditional endpoint telemetry, and it's a category worth building dedicated hunting capability around given how much modern infrastructure has shifted into this space. A hunt hypothesis worth running: review for API calls associated with broad enumeration of IAM policies or storage resources, particularly from credentials or roles that don't normally perform this kind of broad enumeration as part of their legitimate function.

**Treating Discovery Findings as Prioritization Signals for What Comes Next**

A confirmed discovery finding is genuinely valuable beyond itself, because what an attacker chooses to enumerate tells you something about what they're likely to target next. Say a hunt confirms an attacker enumerated file shares specifically related to a finance department, rather than broadly across the entire environment — that narrows your subsequent hunting priorities meaningfully, suggesting the next stages of the intrusion (lateral movement, collection) are more likely to focus on that specific area than elsewhere, which is worth acting on immediately rather than waiting for those later stages to confirm the same thing independently.

Learning to recognize the volume and pattern signatures that distinguish routine administrative enumeration from active attacker reconnaissance — a distinction that takes real practice against realistic telemetry to build intuition for — is exactly the kind of early-warning hunting skill Threat Hunt Labs develops, catching intrusions at the exact moment they're still deciding where to go next.
