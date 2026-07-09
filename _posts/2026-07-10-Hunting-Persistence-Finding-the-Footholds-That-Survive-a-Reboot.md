---
title: Hunting Persistence — Finding the Footholds That Survive a Reboot
date: 2026-07-10 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Persistence]
META DESCRIPTION: A complete guide to hunting the persistence mechanisms attackers rely on to maintain access across reboots, credential changes, and time.
---

An attacker who's gained access and run code once has nothing durable unless they've also established persistence — some mechanism that survives a reboot, a logoff, or the natural churn of a running system. Persistence hunting matters because the mechanisms available to achieve it are genuinely finite, which is one of the friendlier facts in threat hunting: unlike execution techniques, which can be endlessly creative, there are only so many ways to make something survive a restart on a given operating system.

**Why Persistence Is a Genuinely Finite, Huntable Category**

Where execution techniques can vary almost infinitely in their specific implementation, persistence mechanisms are constrained by the operating system itself — scheduled tasks, registry run keys, service creation, startup folder entries, WMI event subscriptions, and a handful of others cover the overwhelming majority of real-world persistence on Windows systems specifically. This finiteness is genuinely good news for hunters: a hunting program that methodically builds coverage across each known mechanism, rather than assuming novel techniques dominate, closes off most of the realistic persistence options an attacker actually has available.

**Scheduled Tasks: Already Covered, Worth Restating as Part of the Full Picture**

The scheduled task hunt walked through in the beginner's walk-through piece earlier in this series remains one of the highest-value persistence hunts, precisely because it's commonly abused and reasonably well-instrumented if your environment logs Event ID 4698 properly. The key discriminators — task names mimicking legitimate system tasks, unusual binary paths, creation by accounts that don't normally create scheduled tasks — apply broadly across this entire persistence category, not just this one mechanism.

**Registry Run Keys and Their Many Variants**

Registry-based persistence, using run keys and their numerous variants (RunOnce, and various less commonly known registry locations that achieve similar effect), remains a classic mechanism precisely because it's simple and reliable. A hunt hypothesis worth building: monitor registry modification events (Sysmon Event ID 13 covers registry value sets) specifically targeting known persistence-relevant registry paths, filtering for modifications made by processes that don't normally touch these keys as part of legitimate software installation or system administration.

The discrimination challenge here is similar to scheduled tasks — legitimate software installs modify these same registry locations constantly, so the hunt needs to focus on the combination of location, the process making the modification, and the value being set, rather than flagging any registry run key modification as inherently suspicious.

**Service Creation: A Persistence Mechanism With High Privilege Implications**

Creating a new Windows service is a particularly attractive persistence mechanism for attackers because services can run with high privileges and start automatically at boot, before a user even logs in. A hunt hypothesis here: review service creation events (Event ID 7045 or 4697 depending on your logging configuration) for services with unusual naming conventions, binary paths outside standard system directories, or creation by accounts that don't normally have or use service creation privileges. Say a hunt surfaces a new service created with a name closely mimicking a legitimate Windows component but pointing to a binary in a user's temporary directory — that's a textbook example of exactly this technique, and it's a pattern worth building a standing detection from once confirmed, feeding back into the detection engineering loop covered in earlier pieces.

**WMI Event Subscriptions: The Quieter, Less-Hunted Mechanism**

WMI event subscriptions represent a persistence technique that's genuinely less commonly hunted than the mechanisms above, largely because it requires slightly more specialized knowledge to query for effectively and doesn't generate as familiar an event log signature as scheduled tasks or services. This makes it a worthwhile area to specifically build hunting capability for precisely because it's less crowded ground — an attacker aware that most defenders focus heavily on scheduled tasks and registry keys might deliberately favor WMI subscriptions exactly because they expect less scrutiny there. A hunt hypothesis worth developing: review WMI subscription creation events for subscriptions that trigger execution of scripts or binaries outside expected administrative tooling, since legitimate use of WMI event subscriptions for this purpose is relatively uncommon in most environments compared to the other mechanisms covered here.

**Startup Folder and Logon Script Abuse: The Simplest, Sometimes Overlooked Option**

The startup folder and logon script mechanisms are almost embarrassingly simple compared to the other techniques covered here, and that simplicity sometimes leads hunters to overlook them in favor of more sophisticated-sounding mechanisms. A basic but worthwhile hunt: periodically review the contents of startup folders across a sample of endpoints for unexpected entries, and review logon script configurations for unauthorized modifications — unglamorous, but cheap to run and occasionally the exact mechanism a less sophisticated but still real intrusion actually used.

**Building Comprehensive Coverage Methodically, Not All at Once**

Given the finite nature of this category, the right approach is methodical, staged coverage-building — pick one mechanism, build a solid hunt for it, confirm the necessary logging exists, then move to the next, tracking progress using the ATT&CK Navigator coverage layer approach covered earlier. Trying to build hunts across every persistence mechanism simultaneously in week one tends to produce shallow, poorly-tuned coverage everywhere rather than solid, reliable detection of even the most common mechanisms.

Systematically building this kind of comprehensive persistence coverage — working through each mechanism with real telemetry until the discrimination between legitimate and malicious use becomes second nature — is exactly the structured, hands-on progression Threat Hunt Labs builds toward, closing off the realistic space of persistence options an attacker actually has available in a real environment.
