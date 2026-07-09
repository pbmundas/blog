---
title: Phase 9 Capstone: Purple Team Mini-Exercise
date: 2026-09-22 12:00:00 +0530
categories: [Purple Teaming]
tags: [Capstone]
META DESCRIPTION: A walkthrough of running a complete purple team mini-exercise, from scenario planning through validated detection deployment.
---

Most purple team "exercises" in training programs stop right after the attack runs and someone says "good, blue caught it." That's not a capstone, that's a demo. A real capstone exercise doesn't end until a detection is written, tested, and sitting in staging because that's the actual point of the whole exercise, and skipping that last mile is how teams end up with purple teaming that feels productive without producing anything durable.

**Scoping the Exercise Before Anyone Touches a Keyboard**

Pick one technique family, not five. I've watched capstone exercises try to cover initial access, lateral movement, and exfiltration all in one session, and the result is shallow coverage of everything and mastery of nothing. Better to go deep on one thing say, persistence via scheduled tasks combined with a specific LOLBin execution chain and actually finish the full cycle from attack through deployed detection.

Before red does anything, blue should document current assumed coverage for the technique. Do we think we'd catch this? What log source do we expect to fire? Writing this down before the exercise starts matters, because it's tempting to retroactively claim "yeah, we sort of expected that gap" after the fact. A written prediction keeps everyone honest about what was actually known versus discovered.

**Running the Attack With Real Documentation Discipline**

Red executes the technique with specific, repeatable steps not a vague "I did some persistence stuff." If it's a scheduled task created via `schtasks.exe` pointing to a payload in a non-standard directory, that's exactly what gets logged: command line, timestamp, host, user context. This level of specificity is what makes the detection-writing phase afterward possible without a lot of reconstruction guesswork.

Blue watches live, not after the fact. This is the entire value of purple teaming over a traditional red team engagement real-time visibility into what did or didn't fire, while the context is still fresh and red can immediately clarify exactly what they just did if something's ambiguous in the logs.

**From "Nothing Fired" to a Working Detection**

Say nothing fires which, honestly, is the more instructive outcome for a training exercise. Now the real capstone work starts. Blue needs to pull the raw logs from the exact time window, identify what data was actually available (was the scheduled task creation event even logged, or is this a data collection gap rather than a rule-writing gap), and draft detection logic from scratch based on what they're looking at.

This is where the exercise either becomes real skill-building or stays theoretical. Writing a detection query against live data pulled from an exercise you just watched happen is a completely different skill than reading about detection writing in the abstract. The behavioral logic has to hold up against the specific log fields available, not an idealized version of what the logs should contain.

**Testing the Detection Before Calling It Done**

Once a detection is drafted, red re-runs the same technique ideally with a small variation, like changing the task name or the payload path, to test whether the detection logic is actually behavioral or just matched the exact original artifact. If it only catches the original run and misses the variation, that's a legitimate finding, and it's a better lesson than getting it right on the first try. It teaches the difference between an IOC-based detection and a genuinely behavioral one.

This retest step is the part almost every rushed exercise skips, and it's the single most valuable five minutes of the whole session. A detection that's never been tested against a variation is a detection you're hoping works, not one you know works.

**Wrapping the Exercise Properly**

The capstone isn't done when the detection fires successfully. It's done when the detection is documented what it catches, what it doesn't, known limitations and staged for eventual production deployment following whatever pipeline your team actually uses. That last step, treating the exercise output like real production work rather than a training artifact that gets discarded, is what separates a capstone that builds real capability from one that's just a well-run simulation with no lasting output.

If you want a structured version of this exact exercise format scenario design, live blue observation, detection drafting, and validation retest ThreatHuntLabs' purple team program runs this as a guided capstone with real feedback on the detections you actually write, not just the attacks you catch.
