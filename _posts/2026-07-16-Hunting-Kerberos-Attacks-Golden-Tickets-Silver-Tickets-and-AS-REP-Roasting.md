---
title: Hunting Kerberos Attacks  Golden Tickets, Silver Tickets, and AS-REP Roasting
date: 2026-07-16 12:00:00 +0530
categories: [Threat Hunting, MITRE ATT&CK]
tags: [Kerberos, Golden Ticket]
META DESCRIPTION: A deep dive into hunting Golden Ticket, Silver Ticket, and AS-REP roasting attacks against Kerberos authentication in Active Directory.
---

Kerberoasting got its own dedicated treatment in the broader credential access piece, but it's really just the entry point into a much deeper set of attacks against the Kerberos protocol itself  attacks that, once successful, can hand an attacker persistence and access that outlasts password resets, account lockouts, and most of the standard incident response playbook. These deserve their own focused treatment, because the stakes and the hunting approach are meaningfully different from garden-variety credential theft.

**Golden Tickets: Forging Trust at the Root**

A Golden Ticket attack exploits the krbtgt account, which signs every Kerberos ticket-granting ticket in a domain. An attacker who's compromised the krbtgt account's password hash  typically requiring domain admin-level access to obtain in the first place  can forge ticket-granting tickets for any user, including accounts that don't actually exist, with any privilege level and any expiration they choose, entirely offline, without ever touching a domain controller until they present the forged ticket for use.

This is what makes Golden Ticket attacks so dangerous and so worth dedicated hunting attention: once the krbtgt hash is compromised, the attacker's access is essentially independent of normal account lifecycle controls. Resetting a compromised user's password does nothing, because the forged ticket was never tied to that user's actual credentials. The only real remediation is resetting the krbtgt account's password twice (due to how Windows maintains two versions of the hash for compatibility), which is disruptive enough that organizations understandably want strong detection before things reach this point rather than relying on remediation after the fact.

**Hunting Golden Ticket Usage**

The classic detection approach looks for tickets with implausible characteristics  a ticket lifetime far exceeding your domain's configured maximum ticket lifetime (the default is commonly ten hours, and a forged ticket with an unusually long or unusual lifetime value is a strong signal), or a ticket presented for a user account that doesn't actually exist in Active Directory, or one presented for an account that's been disabled. A hunt hypothesis worth building: review authentication events (Event ID 4768 and 4769) for ticket lifetime values inconsistent with your domain's configured policy, and cross-reference the account name in each ticket against your actual current Active Directory user list, flagging any mismatch immediately.

Another valuable angle: Golden Tickets are often used well after the initial krbtgt compromise, sometimes months later, which means a hunt specifically looking backward at authentication patterns for accounts that show activity inconsistent with their established behavior  even accounts that appear to be legitimate, existing users  deserves attention, since the forged ticket can impersonate a real account just as easily as a fabricated one.

**Silver Tickets: A Narrower, Quieter Variant**

Silver Tickets are a related but narrower attack, forging a service ticket directly using a specific service account's password hash rather than the domain-wide krbtgt hash. This limits the attacker's forged access to whatever that specific service allows, but it also makes the attack quieter in one specific, important way: because a Silver Ticket doesn't require any interaction with the domain controller's ticket-granting service at all, it can be entirely invisible to logging that only captures domain controller authentication events.

This is the key hunting challenge with Silver Tickets, and it's worth stating honestly: detection here depends heavily on logging at the target service itself, not just domain controller logs. A hunt hypothesis worth building: for high-value services (particularly ones commonly targeted, like file shares or specific application servers), review service-level access logs for authentication patterns inconsistent with the account's established behavior, since domain-level Kerberos logging alone won't surface this attack the way it can surface Golden Ticket usage.

**AS-REP Roasting: Revisiting the Configuration Angle**

AS-REP roasting was introduced briefly in the broader credential access piece, but it deserves a fuller treatment here alongside its Kerberos-attack siblings, since the same hunting principles apply. The attack targets accounts with Kerberos pre-authentication disabled, letting an attacker request authentication data for those accounts without any valid credentials at all, then crack that data offline. A hunt hypothesis worth running: monitor for AS-REQ requests (Event ID 4768 without a corresponding pre-authentication event) at unusual volume or targeting accounts not typically involved in interactive authentication, since a normal environment sees relatively few such requests compared to the volume of standard, pre-authenticated logon activity.

The configuration-side remediation matters as much here as the behavioral hunt  periodically auditing Active Directory for accounts with pre-authentication disabled, and questioning why each one is configured that way, closes the door more reliably than behavioral detection alone, since behavioral detection is inherently reactive to an attack that's already begun.

**Building a Standing Kerberos Health Check**

Given how much of this category benefits from configuration awareness alongside behavioral hunting, a periodic standing review  checking krbtgt password age (a krbtgt hash that hasn't been rotated in years is a meaningfully larger Golden Ticket risk than one rotated regularly), auditing accounts with pre-authentication disabled, and reviewing service account ticket request volumes  pairs naturally with the behavioral hunts covered above. This is one of the clearer cases in this series where administrative hygiene and active hunting genuinely reinforce each other rather than being separate workstreams.

**Why This Category Deserves the Extra Depth**

Kerberos attacks sit at an unusually high-stakes point in the kill chain  successful exploitation here often means domain-wide compromise with persistence that survives normal remediation efforts. That combination of severity and detection difficulty is exactly why this deserves more hunting investment than its relatively narrow technical scope might suggest at first glance.

Building genuine fluency in these Kerberos-specific attack patterns  not just recognizing the names, but understanding exactly why each variant evades certain logging and how to compensate for it  is precisely the kind of high-stakes, detailed practice Threat Hunt Labs works through using realistic Active Directory lab scenarios, where the consequences of missing this category are as serious as anywhere in this entire series.
