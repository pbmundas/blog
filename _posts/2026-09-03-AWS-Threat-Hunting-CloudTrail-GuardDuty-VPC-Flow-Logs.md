---
title: AWS Threat Hunting - CloudTrail, GuardDuty, VPC Flow Logs
date: 2026-09-03 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [AWS]
META DESCRIPTION: Build real AWS hunting capability across CloudTrail, GuardDuty findings, and VPC Flow Logs the telemetry that actually matters.
---

GuardDuty will tell you when something's already gone wrong. CloudTrail will tell you exactly what happened, in exhaustive detail, assuming you know how to ask the right question. VPC Flow Logs will tell you what actually talked to what, at the network layer, when everything else is silent. None of these three sources alone gives you a complete hunting capability in AWS they're complementary, and treating any one as sufficient on its own is how gaps happen.

The teams that hunt well in AWS know which of these three to reach for depending on the question, and increasingly, how to pull all three together into a single investigation.

**CloudTrail is your ground truth, but the volume demands real filtering discipline**

CloudTrail logs essentially every API call made against your AWS account, which is both its greatest strength and the reason naive analysis of it drowns fast. A moderately active account can generate tens of thousands of events a day just from normal automation, CI/CD pipelines, and routine console usage. Hunting effectively here means knowing which event names actually matter for security purposes and filtering aggressively around them rather than trying to review the firehose.

`CreateAccessKey`, `AttachUserPolicy`, `PutRolePolicy`, and `AssumeRole` events involving cross-account access are consistently high-value starting points, because they represent the actual mechanics of privilege escalation and persistence in AWS IAM. A hunt worth running regularly: `CreateAccessKey` events for IAM users that already have console access and haven't needed programmatic access keys before an account that's used SSO login exclusively for the last year suddenly generating a new access key pair is a strong persistence indicator, since attackers frequently create access keys specifically because they survive password rotations and don't require MFA the way console access typically does.

**GuardDuty findings deserve investigation, not just triage-and-close**

GuardDuty is genuinely good at what it does its findings are generally high-confidence, built from a combination of threat intelligence feeds, anomaly detection, and known attack patterns specific to AWS. The mistake teams make is treating a GuardDuty finding as the end of the investigation rather than the start of one. A finding like `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` tells you credentials were likely used outside the instance they belonged to it doesn't tell you what was done with them afterward, and that's exactly the gap CloudTrail analysis needs to fill immediately.

The workflow that actually closes these investigations properly: take the finding's implicated access key or role, then pivot into CloudTrail filtered on that specific credential across the surrounding time window, building out everything that credential actually did which S3 buckets it touched, whether it made any IAM changes, whether it spun up new infrastructure. A GuardDuty finding without this CloudTrail follow-up gets you maybe a third of the actual picture, and closing a finding at that point is how real damage gets missed.

**VPC Flow Logs fill the gap both of the above genuinely can't touch**

CloudTrail and GuardDuty both live at the control plane and API layer they tell you about actions taken against AWS services. Neither tells you much about actual network traffic flowing between resources, which is exactly where VPC Flow Logs come in, and it's a source a lot of AWS hunting programs underuse relative to how much value it actually carries.

The classic hunt here mirrors on-prem lateral movement analysis directly: unusual traffic patterns between EC2 instances or across subnets that shouldn't normally be talking, particularly on ports associated with lateral movement techniques rather than the application's documented architecture. An instance in a public-facing web tier suddenly initiating connections to instances in a database subnet on a port that isn't the expected database port is worth investigating immediately that's not how the application is supposed to talk to itself, and Flow Logs are the only one of these three sources that would ever surface it, since neither CloudTrail nor GuardDuty operates at that network layer.

**S3 access patterns deserve a dedicated hunt of their own**

Data exfiltration in AWS environments frequently runs through S3, given how much organizational data ends up sitting in buckets, sometimes with permissions that are looser than anyone realized until it's too late. CloudTrail S3 data events assuming you've actually enabled them, since they're off by default and carry additional cost, a gap that catches a lot of organizations off guard during an incident let you hunt for unusual `GetObject` volume against sensitive buckets, particularly from IAM principals or roles that don't normally touch that specific bucket at all.

A hunt worth standing up: baseline which principals normally access which buckets, then flag any principal accessing a bucket for the first time combined with a request volume that's high relative to that bucket's typical traffic. Say a Lambda execution role that's only ever read from one specific configuration bucket suddenly pulls two thousand objects from a bucket containing customer records that combination, first-time access plus volume spike, is exactly the pattern worth an immediate look regardless of whether GuardDuty happened to flag it independently, because it doesn't always.

**Pulling all three sources into one investigation workflow**

The real hunting maturity in AWS shows up when an analyst can move fluidly between these three sources depending on what the current question demands starting with a GuardDuty finding, pivoting to CloudTrail to establish exactly what a compromised credential did, then checking VPC Flow Logs to confirm whether any of that activity involved unexpected network communication between resources. None of these sources alone tells the complete story, and building hunting workflows (and the underlying log correlation infrastructure) that assume you'll need all three together is what separates a mature AWS hunting program from one that's just watching a GuardDuty dashboard and hoping it's enough.

It generally isn't enough on its own, and that gap is exactly where hunting earns its place alongside detection engineering rather than being redundant with it. ThreatHuntLabs' AWS hunting module works through building this three-source correlation workflow against a realistic compromised AWS environment CloudTrail, GuardDuty, and Flow Logs all populated with a genuine, traceable intrusion for you to actually work, not just read about.
