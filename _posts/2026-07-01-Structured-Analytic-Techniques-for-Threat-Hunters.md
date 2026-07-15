---
title: Structured Analytic Techniques for Threat Hunters
date: 2026-07-01 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [analysis techniques, cognitive bias, methodology]
description: How intelligence analysis methods like ACH and devil's advocacy help hunters catch their own cognitive bias before it costs an investigation.
image:
  path: /assets/img/threat-hunting/competing-hypotheses.svg
  alt: "Evidence compared against malicious, administrative, and software explanations"
---



![Evidence evaluated against several competing explanations](/assets/img/threat-hunting/competing-hypotheses.svg)



The most dangerous moment in any hunt isn't when the data's confusing—it's when it isn't, when a pattern jumps out looking exactly like what you expected to find, and you stop questioning it a beat too early. Confirmation bias doesn't announce itself. It feels like clarity. Structured analytic techniques, borrowed almost entirely from the intelligence community, exist specifically to slow that moment down long enough to catch yourself.



## Why Hunters Are Especially Exposed to This
Hunting is inherently hypothesis-first work—you start with an expectation about what you'll find, then go looking for evidence. That's necessary and useful, covered at length in earlier pieces on hypothesis formation. But it also creates a structural vulnerability: once you've committed to a hypothesis, there's a natural pull toward interpreting ambiguous evidence as support for it, and toward stopping the investigation the moment you find something that fits, rather than continuing to test whether it actually holds up against alternative explanations.



This isn't a character flaw specific to careless analysts. It's a well-documented cognitive pattern that affects experienced people just as much as inexperienced ones, sometimes more, because experience builds confidence that outpaces the actual certainty warranted by the evidence in front of you.



## Analysis of Competing Hypotheses, Applied to a Hunt Finding
Analysis of Competing Hypotheses, or ACH, is probably the most directly transferable structured technique for hunting work. Instead of building a case for your leading hypothesis and looking for confirming evidence, you lay out every plausible explanation for what you're seeing—including the boring ones—and score each piece of evidence against all of them simultaneously, specifically looking for evidence that's inconsistent with each explanation rather than evidence that supports your favorite.



Picture a hunt turns up a service account authenticating to a system it's never touched before, at 2am. The instinctive hypothesis might be compromise. ACH forces you to also list: a legitimate automation change nobody documented, a misconfigured monitoring tool generating the account's activity, a genuine but rare business process running that account during a scheduled maintenance window. For each hypothesis, you then check what evidence would be inconsistent with it—does the maintenance window explanation hold up against the specific systems touched, does the automation explanation hold up against the actual command pattern observed. The hypothesis that survives the most attempts to disprove it, rather than the one you first thought of, wins.



## The "Then What" Technique for Catching Premature Closure
A lighter-weight but genuinely useful habit: whenever you're about to close a hunt with a confirmed finding, force yourself to answer "if this hypothesis is wrong, what would that look like, and have I actually checked for it." This isn't a formal named technique in the intelligence literature exactly, but it captures the spirit of several structured approaches in a form that's fast enough to apply on every single hunt, not just the high-stakes ones. Picture a hunt confirms malware based on a process behavior match—the "then what" check asks whether you've actually ruled out a legitimate security tool or monitoring agent producing similar behavior, rather than assuming the match alone is sufficient.



## Devil's Advocacy, Even When You're Hunting Solo
Formal devil's advocacy—assigning someone to deliberately argue against the team's leading conclusion—works well with a team, but most hunters work at least partially alone, and the technique still has value adapted for that reality. Before finalizing a finding, write down the single strongest argument against your own conclusion, as if you were a skeptical colleague reviewing your work rather than the person who did it. This is uncomfortable in a specific, useful way—it's much easier to argue against a stranger's conclusion than your own, and forcing yourself into that adversarial posture toward your own work catches things that simple self-review tends to miss.



## Key Assumptions Check: Naming What You Haven't Verified
Every hunt hypothesis rests on assumptions, some tested and some quietly unexamined. A key assumptions check is the discipline of explicitly listing what you're assuming to be true before trusting a finding—that your logging is actually capturing what you think it is, that a baseline you're comparing against is actually representative, that a data source hasn't silently changed format or coverage since you last relied on it. Picture a hunt concludes an account's behavior is anomalous based on a baseline built six months ago—an assumptions check would flag that the baseline itself needs revalidating before the anomaly claim holds real weight, since six months is enough time for legitimate usage patterns to shift.



## Making These Techniques Actually Stick, Not Just Theoretical
The risk with structured analytic techniques is treating them as a formal exercise reserved for major investigations, then forgetting them entirely for routine hunting work—which is exactly where cognitive bias does its quietest damage, in the hunts that feel too mundane to warrant extra scrutiny. Building a lightweight version of one or two of these techniques into your standard hunt documentation template, so the "what else could explain this" question gets asked by default rather than only when something feels unusually high-stakes, is what actually makes this discipline durable rather than performative.



## Run a competing-hypotheses table



For one ambiguous finding, compare at least three explanations: malicious activity, authorized administration, and automated software. List evidence that is consistent or inconsistent with each. Weight evidence that discriminates between explanations more heavily than evidence all three would produce. Record the key assumption most likely to change your conclusion.



Structured techniques do not remove judgment. They expose where judgment, missing evidence, and cognitive bias are shaping the answer.
