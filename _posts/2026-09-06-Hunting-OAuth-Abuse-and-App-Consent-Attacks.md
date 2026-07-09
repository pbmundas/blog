---
title: Hunting OAuth Abuse and App Consent Attacks
date: 2026-09-06 12:00:00 +0530
categories: [Threat Hunting, Identity]
tags: [OAuth]
META DESCRIPTION: Illicit OAuth consent grants bypass MFA and survive password resets. Here's how to hunt malicious app consent in Entra ID specifically.
---

Reset the password. Force MFA re-registration. Kill every active session. And the attacker's still reading the mailbox, because none of that touches the OAuth token a user handed over willingly three weeks ago to what looked like a document-signing app. That's the uncomfortable reality of illicit consent grant attacks, and it's exactly why they've become one of the more attractive techniques for anyone who's put real thought into persistence.

The mechanics are simple enough to explain in one sentence: trick a user into approving an OAuth application's permission request, and that application now has whatever access it asked for often mail read, file access, or offline access independent of the user's password entirely. Hunting this requires looking somewhere most identity-focused monitoring wasn't originally built to look.

**Understanding what a consent grant actually gives an attacker**

Before hunting for this, it's worth being precise about what's at stake, because the scope varies enormously based on what permissions got approved. A consent grant for `Mail.Read` gives read access to the mailbox bad, but bounded. A grant including `offline_access` means the attacker's refresh token keeps working indefinitely, or until explicitly revoked, regardless of how many times the user changes their password. A grant for `Mail.ReadWrite` and `Mail.Send` on top of that lets the attacker not just read mail but send from the compromised account too, which opens the door to using that access for further phishing or BEC targeting the victim's own contacts.

This range matters for prioritizing your hunt not every consent grant deserves the same urgency, and building your detection logic to weight permission scope heavily, rather than treating every new app consent identically, focuses analyst attention where it actually matters.

**Hunting newly consented applications with broad or sensitive scopes**

The core hunt: pull Entra ID audit logs for `Consent to application` events, and filter for applications requesting `Mail.Read`, `Files.ReadWrite.All`, `offline_access`, or similarly broad scopes. Cross-reference the consenting application against whether it's a Microsoft-verified publisher unverified publisher status isn't automatically malicious, plenty of legitimate small vendors haven't gone through verification, but it's a meaningful risk multiplier worth factoring into your scoring rather than a hard block.

Timing context matters enormously here too. A consent grant that happens within minutes of the user clicking a link in an email, especially outside normal working hours, is a very different finding than the same grant happening during a documented software rollout your IT team pushed to the whole organization. If you've got email gateway logs available, correlating consent grant timestamps against recent inbound emails to that same user closes this loop directly a phishing email with a consent-grant link followed by the actual grant fifteen minutes later is close to a confirmed case.

**Admin consent bypass and the tenant-wide risk it represents**

Some attacks target admin consent specifically rather than tricking individual users either by compromising an account with admin consent privileges, or by exploiting tenants where user consent settings are configured more permissively than they should be, allowing users to consent to applications requesting fairly broad permissions without any admin review at all. This is a configuration gap worth auditing directly rather than waiting to catch it reactively: check your tenant's user consent settings and tighten them to require admin review for anything beyond a low-risk permission tier, if that isn't already the case.

Where admin consent does happen, whether legitimate or attacker-driven, it deserves the same scrutiny as any other privileged action who granted it, was it tied to a known application onboarding process, and does the requested permission scope match what that application's stated purpose would actually require. An application that claims to be a simple calendar scheduling tool requesting full directory read access is a mismatch worth questioning regardless of who approved it.

**Application behavior after consent is where the real confirmation happens**

A consent grant alone tells you access was given, not that it's being abused. The confirming evidence comes from watching what the application actually does with that access afterward API call patterns attributable to the application's service principal, visible in Entra ID sign-in logs under the non-interactive sign-ins category, which a lot of hunters forget to review separately from interactive user sign-ins.

An application that consented to `Mail.Read` and then generates a burst of Graph API calls pulling mailbox content across an unusually short window, especially shortly after the grant, is exhibiting exactly the behavior you'd expect from an attacker's malicious app immediately exfiltrating whatever it can grab before someone notices and revokes access. Building a standing hunt around non-interactive sign-in volume per application, baselined against that application's normal usage pattern, catches this follow-through activity even in cases where the initial consent grant itself didn't look obviously suspicious at the time.

**Remediation has to include actual token revocation, not just app removal**

Worth stating plainly because it trips people up during real incidents: removing a malicious application's consent grant from the Entra ID admin portal doesn't always immediately kill every active token that application already holds, depending on token type and caching behavior. Confirming actual revocation checking that subsequent API calls from the application's service principal genuinely fail is a step that has to be part of your response runbook, not an assumption you make because you clicked the remove button.

OAuth consent abuse remains under-hunted relative to how effective it's proven to be, mostly because it lives in a log source application consent and non-interactive sign-in events that a lot of identity monitoring programs haven't fully incorporated yet. ThreatHuntLabs' OAuth abuse hunting module walks through building consent-grant hunting, permission-scope risk scoring, and post-consent behavior analysis against a realistic Entra ID tenant with a genuine illicit consent scenario baked in.
