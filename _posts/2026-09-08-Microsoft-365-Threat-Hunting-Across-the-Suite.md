---
title: Microsoft 365 Threat Hunting Across the Suite
date: 2026-09-08 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [Microsoft 365]
META DESCRIPTION: M365 compromise rarely stays in one app. Here's how to hunt across Exchange, SharePoint, and Teams using Unified Audit Log data.
---

An attacker who lands in a Microsoft 365 tenant doesn't stay politely inside Exchange. They read the mailbox, sure, but they also poke around SharePoint looking for anything useful, check Teams chat history for shared credentials or sensitive conversations, and quietly set up a mail forwarding rule on the way out the door. Hunting M365 as though email is the whole attack surface misses most of what a competent attacker actually does once they're in.

The Unified Audit Log is where almost all of this shows up, assuming it's properly enabled and retained long enough to be useful a gap that catches more organizations than it should, since default retention windows are shorter than most incident timelines actually need.

**Mailbox rule creation remains one of the highest-value hunts in the whole suite**

This one's almost a cliché at this point among people who do this work, and it stays on every list for a reason: inbox rules that forward mail externally, or that silently delete/move incoming messages to obscure folders, are one of the most consistent indicators of a compromised mailbox across essentially every phishing and BEC investigation. Attackers set these up specifically to maintain visibility into ongoing conversations waiting for an invoice thread, watching for password reset emails without the victim noticing anything's different about their inbox day to day.

The hunt: `New-InboxRule` and `Set-InboxRule` events in the Unified Audit Log where the rule action includes `ForwardTo`, `RedirectTo`, or `MoveToFolder` targeting anything other than standard, well-known folders. External forwarding rules specifically deserve a hard rule with minimal tolerance say your organization decides legitimate business need for external auto-forwarding is genuinely rare, maybe a handful of cases a year with documented justification and treats any rule creation outside that known list as an immediate investigation trigger, not a queued alert for next week.

**SharePoint and OneDrive sharing activity needs volume-and-scope analysis, not just link creation alerts**

External sharing in SharePoint and OneDrive is a legitimate, constant business activity, which makes naive "alert on external share" rules useless at any real scale you'd generate hundreds of alerts a week in an active organization. The hunt that actually works layers volume against sensitivity: a user sharing one document externally is routine; the same user sharing forty documents externally within an hour, especially from a site or library containing anything flagged as sensitive through your DLP labeling, is a different story entirely.

"Anyone with the link" sharing settings deserve specific attention beyond named-recipient sharing, because they represent the broadest possible exposure a document shared this way is accessible to anyone who obtains the link through any means, not just the intended recipient. Hunting for `AnonymousLinkCreated` events against sensitive content libraries, correlated against whether the creating account shows any other signs of compromise from the sign-in or mailbox rule hunts above, closes the loop between "this happened" and "this happened because the account is compromised."

**Teams activity is the newest addition to this hunting picture and still underused**

Teams generates its own rich set of audit events message activity, external access grants, app installations within Teams and it's genuinely the newest of these data sources to get serious hunting attention, partly because Teams itself is a relatively newer addition to a lot of organizations' collaboration stack compared to Exchange and SharePoint's much longer history.

External access configuration changes in Teams deserve a specific watch: a tenant-level or team-level setting change that opens external collaboration more broadly than your organization's baseline policy is worth flagging, the same way an NSG rule change or a firewall modification would be in infrastructure hunting. Third-party app installations within Teams, particularly ones requesting broad permissions similar to the OAuth consent abuse pattern covered elsewhere in this series, deserve the same scrutiny Teams apps can request Graph API permissions just like standalone OAuth applications, and that attack surface is still relatively fresh territory for a lot of hunting programs that haven't extended their consent-abuse hunting logic to cover it yet.

**Cross-application correlation is where M365 hunting actually earns its value**

The real payoff in M365 hunting comes from stitching activity across these applications into a single narrative rather than reviewing Exchange, SharePoint, and Teams as separate silos with separate analysts responsible for each. An account showing a risky sign-in, followed by a new mailbox forwarding rule, followed by unusual SharePoint access to a finance library, followed by a Teams external access change, isn't four unrelated low-priority findings strung together in order, it's a clear account takeover narrative that any one signal alone would likely have gotten dismissed or under-prioritized.

Building this correlation requires getting all of these event types into a single queryable timeline per user identity, which the Unified Audit Log largely supports natively if you're pulling it into a SIEM with reasonable joining capability, rather than treating each M365 service's logs as a separate investigation silo the way a lot of tenant configurations default to.

**Retention is the quiet prerequisite that makes all of this possible**

None of this hunting matters if your Unified Audit Log retention doesn't cover a long enough window to actually catch slow-moving compromises and default retention in a lot of licensing tiers is shorter than most real investigations need, sometimes covering only 90 days when a genuinely patient intrusion might unfold over twice that. Confirming your actual retention configuration, and extending it through E5 licensing or a dedicated logging export pipeline if your current tier falls short, is foundational work that has to happen before any of the hunts above are worth building at all.

M365 compromise touches every application in the suite eventually, and hunting programs that only watch Exchange are working with half the picture at best. ThreatHuntLabs' M365 hunting module walks through building mailbox rule detection, SharePoint sharing anomaly hunting, and cross-application correlation against a realistic tenant with a genuine multi-service compromise scenario the kind of practice that makes the full-suite picture click into place a lot faster than piecing it together app by app during a live incident.
