---
title: "Cloud Threat Hunting Fundamentals"
date: 2026-09-01 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [Cloud]
description: Cloud hunting isn't on-prem hunting with different logs. Here's what genuinely changes and where the fundamentals still hold.
image:
  path: /assets/img/threat-hunting/cloud-control-plane.svg
  alt: "Cloud threat hunting across identity, control plane, workload, and network telemetry"
---



![Cloud hunts connecting identity control-plane workload and network telemetry](/assets/img/threat-hunting/cloud-control-plane.svg)



Ask a hunter who's spent five years doing on-prem Windows and network hunting to walk through a cloud incident and watch what happens. Half the instincts transfer cleanly. The other half actively mislead. There's no perimeter firewall to watch traffic cross, no domain controller to anchor authentication analysis around, and the "network" in question might be a set of API calls that never touch a packet capture tool at all. Cloud hunting isn't a reskin of on-prem hunting it's a genuinely different terrain with its own failure modes.



That said, the underlying discipline doesn't change. You're still building hypotheses, still baselining normal, still chasing anomalies with a specific investigation in mind rather than staring at a dashboard hoping something jumps out. What changes is where the evidence lives and what "normal" actually looks like.



## Identity is the new perimeter, and it needs to be treated that way
In an on-prem world, network segmentation and physical access controls did a lot of defensive work by default. In the cloud, identity and access management is doing almost all of that work instead a compromised credential with the right IAM permissions can reach production databases, spin up infrastructure, or exfiltrate data without ever touching anything resembling a traditional network boundary.



This means cloud hunting leans heavily on identity-centric analysis in a way on-prem hunting historically didn't have to. Unusual authentication patterns a login from a geography that account has never used, a service account suddenly being used interactively, an access key that's normally quiet generating a burst of API calls at an unusual hour carry outsized weight here, because identity compromise is so often the entire attack in cloud environments, not just the entry point to something else. Say a developer's access key, normally used only from CI/CD pipeline infrastructure, starts making API calls from a residential IP range that mismatch alone, with zero other context, is often enough to justify an immediate investigation.



## Ephemeral infrastructure breaks a lot of assumptions built for persistent hosts
On-prem hunting assumes hosts stick around long enough to build a meaningful baseline and to go collect forensic evidence from after the fact. Cloud infrastructure, particularly containerized and serverless workloads, might exist for minutes. A Lambda function or a container that spins up, does something malicious, and terminates before anyone's even finished triaging the alert is a genuinely different forensic problem than a compromised server sitting on a desk that isn't going anywhere.



This pushes the emphasis toward logging everything centrally and treating the log itself as the primary evidence source, rather than planning to go collect artifacts from the host after the fact the way you would with an on-prem endpoint. If your logging pipeline has gaps and a lot of organizations discover this only after an incident ephemeral infrastructure can compromise, do damage, and disappear without leaving anything to forensically examine beyond whatever got logged centrally in the moment. Getting comprehensive, centralized logging genuinely right, before you need it, matters more in cloud environments than almost anywhere else in this whole discipline.



## Shared responsibility means your visibility has real edges
Every cloud provider draws a line somewhere between what they secure and monitor versus what's the customer's job, and that line varies by service model IaaS gives you more visibility responsibility than a fully managed PaaS or SaaS offering does. A hunter moving into cloud work for the first time needs to understand exactly where that line sits for each service they're responsible for, because assuming visibility you don't actually have is a dangerous blind spot, and it's a different blind spot for every service.



Managed database services are a good example you often don't get the same query-level audit logging by default that you'd configure on a self-managed database, and turning it on sometimes has to happen explicitly and sometimes carries a real cost implication that makes teams skip it. Knowing which of your cloud services have logging gaps by default, and closing those gaps deliberately rather than discovering them during an incident, is foundational work that has to happen before any hunting program in the cloud is worth much.



## Multi-cloud and hybrid environments multiply the complexity fast
Most real organizations aren't running one cloud, cleanly. They're running some mix of on-prem, AWS, Azure, maybe a SaaS platform with its own audit logging, all with different log formats, different retention defaults, and different native security tooling. A hunting program that only knows one platform deeply is going to have real blind spots the moment an incident spans environments, which happens more often than teams expect a compromised on-prem credential getting used to pivot into a cloud environment via federated identity is a genuinely common attack path now, not an edge case.



Building normalization into your logging pipeline early getting CloudTrail, Azure Activity Logs, and whatever on-prem sources you have into a common schema your analysts can actually query consistently pays off enormously the first time an investigation has to follow an attacker across that boundary. Trying to build that normalization mid-incident is a bad time to discover your log formats don't line up.



## The fundamentals still decide whether any of this works
None of the cloud-specific complexity above matters if the basic hunting discipline isn't there underneath it hypothesis-driven investigation, baseline-before-anomaly thinking, correlating multiple weak signals instead of chasing single alerts. Cloud hunting is genuinely harder in some specific, concrete ways, but it's not a separate discipline requiring an entirely different mindset. It's the same mindset applied to terrain that doesn't behave the way on-prem terrain does.
