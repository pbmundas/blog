---
title: Hunting Persistence  A Deep Dive Into Registry, Startup, and WMI
date: 2026-07-11 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [WMI, Persistence, Registry]
META DESCRIPTION: A focused, practical deep dive into hunting the three most common Windows persistence locations attackers actually rely on.
---

The broad persistence overview covered elsewhere in this series touches most of the major mechanisms lightly. This piece goes deeper on three specifically  registry-based persistence, startup folders, and WMI subscriptions  because between them, they cover an outsized share of the persistence you'll actually encounter in real investigations, and each deserves more query-level specificity than a survey piece can give.

**Registry Persistence: Knowing Which Keys Actually Matter**

The classic Run and RunOnce keys under both HKCU and HKLM get the most attention, and rightly so  they're simple, reliable, and heavily used. But a genuinely thorough registry hunt needs to go beyond just these two locations. Windows has a surprising number of lesser-known registry paths that achieve similar autostart behavior  Winlogon notification packages, AppInit_DLLs (largely deprecated on modern systems but still relevant on older ones you might still be running), and various shell extension and browser helper object registrations that execute code without ever touching the more commonly monitored Run keys at all.

A hunt hypothesis worth building specifically: maintain a curated list of the ten to fifteen registry locations most commonly abused for persistence, beyond just the obvious Run keys, and build a query that monitors modifications across all of them rather than just the well-known two. Say your environment logs registry modifications broadly  a query scoped only to the standard Run key location will completely miss a Winlogon Shell value modification, which achieves nearly identical persistence but sits in a location most junior hunters never think to check. This gap is exactly the kind of thing that separates comprehensive registry hunting from a hunt that only catches the textbook example.

**The Value-Content Discrimination Problem**

Once you're monitoring the right locations, the actual discrimination challenge is the same one covered in the broader persistence piece  legitimate software modifies these same keys constantly during installation. The sharper signal comes from examining the actual value being set, not just that a modification occurred. A registry Run key entry pointing to a path in `C:\Windows\System32` associated with a digitally signed, well-known executable is low priority. The same key pointing to an unsigned executable in a user's AppData or Temp directory, especially one with a randomly generated or suspicious-looking filename, deserves immediate attention. Building this path-and-signature check directly into your hunt query, rather than relying on manual review of every hit, meaningfully reduces the noise you're wading through.

**Startup Folders: Simple Enough to Be Genuinely Underhunted**

Startup folder persistence  placing a file directly in a user's or the all-users startup folder  is almost too simple to be interesting, and that's exactly why it deserves dedicated attention rather than being dismissed as a lesser technique. A hunt hypothesis worth running periodically: enumerate the contents of startup folders across a representative sample of endpoints (or all of them, if your EDR platform supports bulk file inventory queries), and flag any entries that aren't part of your known, approved software baseline.

The practical challenge here is less about detection logic and more about maintaining an accurate baseline of what's expected to be there. Say your organization has twelve different legitimate applications that place startup entries across various endpoint configurations  building and maintaining that baseline list, then flagging deviations from it, is a more sustainable long-term hunt than trying to evaluate each startup entry's legitimacy from scratch every time the hunt runs.

**WMI Event Subscriptions: The Mechanism That Rewards Deliberate Practice**

WMI-based persistence deserves the deepest treatment of the three, precisely because it's the least intuitive to query for and the most likely to be missed by hunters who haven't specifically built this skill. A WMI event subscription persistence mechanism consists of three linked components  an event filter (defining the trigger condition, like system startup), an event consumer (defining the action to take, like executing a script), and a filter-to-consumer binding connecting the two. Querying for any one component in isolation gives an incomplete picture; a thorough hunt needs to enumerate all three and understand how they connect.

A hunt hypothesis worth developing: pull all WMI event consumers configured on a sample of endpoints  these are relatively rare in legitimate use compared to the sheer volume of scheduled tasks or registry entries you'd normally sift through  and manually review each one, since the overall volume tends to be low enough that manual review of every hit is actually feasible, unlike the higher-volume mechanisms elsewhere in this series. Say a hunt across five hundred endpoints turns up only six active WMI event consumers total, four tied to known legitimate monitoring software and two entirely unaccounted for  that low base rate is exactly what makes WMI persistence hunting tractable even without heavy automated filtering.

**Cross-Referencing All Three for a Genuinely Comprehensive Sweep**

The strongest version of this hunt doesn't treat these three mechanisms as separate exercises but runs them as a coordinated sweep, since a sophisticated attacker establishing redundant persistence might use more than one mechanism simultaneously specifically so that removing one doesn't fully evict them. Finding an unexplained registry Run key entry should prompt a check of startup folders and WMI subscriptions on that same host, not just closure of the single finding in isolation.

Building genuine fluency across all three of these specific mechanisms  not just knowing they exist, but knowing exactly where to look and what legitimate baseline looks like for each  is precisely the kind of detailed, hands-on practice Threat Hunt Labs works through, closing the gap between a general awareness of persistence techniques and the query-level specificity that actually finds them in real telemetry.
