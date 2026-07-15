---
title: "Linux Threat Hunting Fundamentals"
date: 2026-08-18 12:00:00 +0530
categories: [Threat Hunting, Endpoint Security]
tags: [Linux]
description: A practical walkthrough of core Linux threat hunting artefacts auth logs, cron, shell history, and process trees analysts actually use.
---

## What you will learn

- Explain the attacker behavior and why it matters to the environment.
- Map the behavior to required endpoint, identity, network, or cloud evidence.
- Build a scoped hypothesis and distinguish malicious activity from legitimate administration.

Most SOC teams grew up hunting Windows and it shows. Ask an analyst to walk you through a suspicious `lsass.exe` access chain and they'll do it without blinking. Ask the same analyst to explain what's odd about a cron entry and you'll often get a shrug. Linux runs the majority of internet-facing infrastructure and most cloud workloads, and the hunting discipline around it still lags badly behind Windows-focused practice at a lot of organizations.

The good news is that Linux's artifact surface, while different, is actually more consistent across distributions than people expect once you know where to look. Build the fundamentals in a handful of locations and you cover a surprising amount of ground.

## Auth logs are your starting point, but read them for pattern, not just failure
`/var/log/auth.log` on Debian-based systems, `/var/log/secure` on RHEL-based ones this is where SSH authentication, sudo usage, and PAM events land. Everyone knows to look for repeated failed logins. Fewer people look closely at successful logins that don't match the account's normal pattern.

A service account that's never logged in interactively suddenly getting an SSH session at 3 a.m. is worth ten times more attention than another round of brute-force noise from a scanning bot, which is honestly just background radiation on any internet-facing box. Pull the source IP, the auth method (key versus password), and cross-reference against that account's history. If `backup-svc` has authenticated via key from one internal jump host for eight months and suddenly authenticates via password from an external IP, that's not a false positive worth suppressing that's the whole hunt in one line.

## Cron, systemd timers, and the persistence mechanisms people forget to check
Cron gets attention. `/etc/cron.d`, user crontabs under `/var/spool/cron`, `/etc/crontab` itself these get reviewed. What gets missed constantly is systemd timers, which have quietly become the more common persistence mechanism on modern distros precisely because defenders check cron out of habit and skip `/etc/systemd/system/*.timer` and the corresponding `.service` units.

Say an attacker drops a `.timer` unit named something boring like `sys-maintenance.timer` that fires every fifteen minutes and calls a service unit executing a base64-decoded payload that survives most cron-only reviews entirely. The hunt here is straightforward once you know to do it: enumerate every enabled timer with `systemctl list-timers --all`, then manually review any that weren't part of your baseline OS install or a known application deployment. Do this once and you'll usually find at least one thing you didn't expect, even on a clean box abandoned monitoring agents are a common false-positive source, so build your baseline before you go hunting for real incidents.

## Shell history is unreliable evidence, and that unreliability is itself a signal
Bash and zsh history files are trivially easy for an attacker to clear, disable, or manipulate `unset HISTFILE`, `export HISTSIZE=0`, or a straight `rm ~/.bash_history` are all one-liners a script kiddie knows. Which means don't treat an empty or missing history file as "nothing happened here." Treat it as its own indicator.

Cross-reference: does the account's `.bash_history` file exist but show a suspicious gap say, no entries for a six-hour window during which auth logs show an active session? Check the file's modification and access timestamps against the session's actual logon and logoff times from auth.log. A history file that was clearly truncated or timestamp-manipulated during an active session is a stronger indicator than most of what actually shows up inside a history file, ironically.

## Process trees and the auditd gap most environments never close
Without auditd configured with a reasonable ruleset, Linux process execution logging is basically nonexistent by default, which puts most organizations in a worse starting position than they are on Windows with Sysmon deployed. If you haven't configured `execve` auditing via auditd rules, that's the single highest-leverage change you can make before doing any serious Linux hunting everything else on this list gets dramatically more useful once you have process lineage to correlate against.

Once that's in place, the hunt looks familiar to anyone who's done Windows process tree analysis: unexpected parent-child relationships (a web server process spawning a shell), execution from world-writable directories like `/tmp` or `/dev/shm`, and processes running with names that mimic legitimate system binaries but live in the wrong path. `/tmp/.X11-unix/ps` masquerading as the real `ps` binary is a pattern that's been around for over a decade and still works on environments that don't check binary paths, not just binary names.

## Network connections from places that shouldn't be talking to the internet
Internal application servers that have no business making outbound connections suddenly reaching out to unfamiliar IPs is a classic Linux compromise indicator, and it's one of the easier ones to build detection logic around if you have any kind of network flow visibility. The investigation step that matters is correlating that outbound connection back to the process that initiated it `ss -tlnp` or equivalent at the time of the connection, or better, ongoing eBPF-based monitoring if your environment supports it because the connection alone tells you something's wrong, but the process tells you what.

Linux hunting rewards the same discipline Windows hunting does: build a baseline before you go looking for anomalies, because "unusual" only means something relative to what's normal in your environment. Start with auth logs and persistence mechanisms, get auditd properly configured, and the rest of the investigation workflow starts falling into place a lot faster than people expect.

ThreatHuntLabs' Linux fundamentals track covers each of these artifact locations with guided labs against real compromised hosts a solid next step if you want the fundamentals to actually stick.


## Build the hunt

Write one hypothesis using behavior, target, and expected evidence. Define the asset and time scope, required fields, likely benign explanations, and an escalation threshold. Test first in an authorized lab or approved dataset, then record what the available evidence can and cannot prove.

## Key takeaway

This lesson should leave you with a repeatable way to ask a narrower question, examine the right evidence, and improve future hunting or detection work.
