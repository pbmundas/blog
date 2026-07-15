---
title: "Hunting Process Injection: The Cornerstone of Modern Evasion"
date: 2026-07-14 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [CTI, Process Injection]
description: A deep dive into detecting process injection and hollowing, the evasion technique underpinning much of modern malicious tradecraft.
---

## What you will learn

- Explain the attacker behavior and why it matters to the environment.
- Map the behavior to required endpoint, identity, network, or cloud evidence.
- Build a scoped hypothesis and distinguish malicious activity from legitimate administration.

If there's one technique worth understanding at a genuinely deep level rather than a surface pass, it's process injection. It shows up across an enormous range of malware families and actor sophistication levels, precisely because injecting malicious code into a legitimate, trusted process is one of the most effective ways to make malicious activity look like it's coming from something benign.

## Why Process Injection Is So Attractive to Attackers
The core appeal is straightforward: if malicious code executes within the memory space of a legitimate, trusted process  say, explorer.exe or svchost.exe  then any detection logic keyed purely on process identity (this process name is trusted, therefore its behavior is trusted) gets fooled by design. The malicious code inherits the legitimate process's identity, its typical network behavior patterns, and often escapes scrutiny that would immediately apply to a genuinely new, unrecognized process launching the same actions.

## Classic DLL Injection: The Baseline Technique
The simplest form, DLL injection, involves forcing a legitimate process to load a malicious dynamic-link library, typically via API calls like `CreateRemoteThread` combined with `WriteProcessMemory`. This combination of API calls, while individually used for legitimate purposes in some software, is relatively uncommon as a paired sequence targeting another process's memory space in most normal application behavior. A hunt hypothesis worth building, assuming EDR-level API call visibility: flag instances where a process writes memory into another process and subsequently creates a remote thread in that same target process, particularly where the source and target processes have no established, legitimate relationship (an antivirus product injecting into a browser for legitimate monitoring purposes looks different, contextually, than an unrelated process doing the same thing to explorer.exe).

## Process Hollowing: A More Sophisticated Variant
Process hollowing takes this further  an attacker launches a legitimate process in a suspended state, then replaces its memory contents entirely with malicious code before resuming execution, so the process appears completely legitimate from the outside (correct name, correct file path, correct parent process) while its actual running content has been substituted. This is genuinely harder to detect through simple API monitoring alone, since the technique is specifically designed to preserve every surface-level indicator of legitimacy.

A hunt hypothesis worth building here focuses on discrepancies between what a process claims to be and what it's actually doing  comparing the loaded modules or memory region characteristics of a running process against what's expected for a legitimate instance of that same executable. Say a genuine svchost.exe process normally loads a predictable, consistent set of modules given its specific service configuration  a hollowed instance, with its memory substituted, will often show an inconsistent or unexpected module list compared to genuine instances of the same process on other hosts, which is exactly the kind of comparison a hunter can build if their EDR platform surfaces loaded module information.

## Process DoppelgÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¤nging and Newer Variants
More advanced injection variants, including process doppelgÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¤nging and various techniques exploiting transactional NTFS or other lesser-known Windows subsystems, continue to emerge as older, well-documented techniques get better detected and attackers shift toward newer, less-instrumented mechanisms. This is a category where staying current on published research genuinely matters more than in most other hunting areas covered in this series, since the specific technical implementation shifts meaningfully faster here than in, say, persistence mechanisms, which are constrained by a more finite set of OS-level options.

## Behavioral Indicators That Cut Across Injection Variants
Regardless of the specific injection technique, several behavioral indicators tend to recur across most variants and are worth building generalized hunting logic around rather than chasing each new named technique individually. Unusual network connections originating from a process that doesn't normally make that kind of connection (a legitimate system process suddenly reaching out to an external IP it has no documented reason to contact) is one of the more reliable cross-cutting signals, since the injected code's actual malicious behavior  command-and-control communication, data staging  still has to happen somewhere, even if the process identity making that connection has been successfully spoofed through injection.

## Memory Scanning as a Complement to Behavioral Hunting
Where your EDR platform supports it, periodic memory scanning across running processes  looking for characteristics like unusual memory region permissions (executable memory that was allocated in a way inconsistent with the legitimate process's normal behavior) or known malicious code patterns loaded in memory without a corresponding legitimate file on disk  provides a complementary hunting approach to purely behavioral, network-based detection. This tends to be resource-intensive to run broadly and continuously, making it better suited to a targeted hunt against specific high-value hosts or hosts already flagged as suspicious by other means, rather than a continuous sweep across an entire environment.

## Why This Technique Rewards Deep Investment
Given how frequently process injection underpins the actual execution of malicious code across a huge range of otherwise very different intrusions, time invested in building genuinely solid hunting capability here pays off disproportionately compared to narrower, more specific techniques  a hunter who deeply understands injection patterns can often recognize a genuinely novel malware family's behavior even without any prior signature or intelligence specific to that exact sample, purely because the underlying injection mechanics tend to leave similar behavioral traces regardless of the specific payload riding on top of them.


## Build the hunt

Write one hypothesis using behavior, target, and expected evidence. Define the asset and time scope, required fields, likely benign explanations, and an escalation threshold. Test first in an authorized lab or approved dataset, then record what the available evidence can and cannot prove.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
