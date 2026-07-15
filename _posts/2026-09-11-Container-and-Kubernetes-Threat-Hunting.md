---
title: "Container and Kubernetes Threat Hunting"
date: 2026-09-11 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [Kubernetes]
description: Containers live for minutes, not months. Here's how to build real threat hunting capability across container and Kubernetes environments.
---



![Container and Kubernetes hunting across identity API activity workloads and network telemetry](/assets/img/threat-hunting/cloud-control-plane.svg)



A compromised container might exist for four minutes before the orchestrator kills it and spins up a replacement. That's not a hypothetical edge case it's the normal operating rhythm of a lot of Kubernetes environments, and it means container hunting has to work fundamentally differently from anything built around the assumption that a compromised asset will sit around long enough to investigate at leisure.



This is genuinely one of the more technically demanding hunting domains in this whole series, because the attack surface spans the container runtime, the orchestration layer, and the underlying host, often simultaneously, and an attacker moving through one layer can pivot into another in ways that don't map cleanly onto any single hunting discipline covered so far.



## Runtime behavior monitoring has to happen continuously, not retrospectively
Given how short-lived a lot of container workloads are, the forensic model of "go collect evidence from the compromised asset after the fact" often just doesn't work the container may not exist anymore by the time anyone's investigating. This pushes container hunting hard toward continuous runtime monitoring rather than after-the-fact analysis, using tools like Falco or equivalent eBPF-based runtime security agents that capture system call activity as it happens and ship it somewhere durable before the container disappears.



The specific patterns worth hunting for at the runtime layer: a container spawning a shell process when its expected behavior never involves interactive shell access, a container process attempting to write to locations outside its expected filesystem paths, or unexpected outbound network connections from a workload that should have a tightly scoped, predictable set of destinations. Say a web application container that normally only talks to its database and a payment processor's API suddenly opens a connection to an unfamiliar external IP on a high port that's a strong signal worth immediate investigation, and it's exactly the kind of thing runtime monitoring catches that would otherwise vanish along with the container itself.



## Kubernetes API server audit logs are your control-plane visibility
The Kubernetes API server audit log captures every request made against the cluster's control plane pod creation, RBAC changes, secret access, exec commands into running containers. This is genuinely one of the richest data sources in the whole container hunting picture, and it's also frequently under-configured, with a lot of clusters running with minimal or no audit logging enabled by default depending on how the cluster was provisioned.



`kubectl exec` events deserve particular attention an interactive exec session into a running container is a legitimate debugging action taken by engineers regularly, but it's also exactly what an attacker does once they've got cluster access and want to interact with a running workload directly. Correlating exec events against whether they came from a known engineering account during a documented debugging session, versus an unfamiliar service account or an account that's never exec'd into anything before, separates routine operations from something worth escalating. RBAC changes granting broad permissions particularly anything approaching cluster-admin deserve the same scrutiny as IAM privilege escalation in any cloud environment, because Kubernetes RBAC misconfiguration is a consistently common path to full cluster compromise.



## Container image provenance matters more than most teams treat it
A meaningful share of container compromises trace back to the image itself rather than a runtime exploitation a base image pulled from an untrusted registry that already contained malware, or a legitimate image that got tampered with somewhere in a compromised build pipeline before it ever reached your cluster. Hunting here shifts toward supply chain analysis: are images being pulled from approved registries only, do deployed images match known-good hashes from your build pipeline, and is there any deviation between what your CI/CD system built and what's actually running in the cluster.



Image scanning at deploy time catches known vulnerabilities, but it doesn't catch a deliberately backdoored image that wasn't flagged by any CVE database, because there's no vulnerability being exploited the malicious behavior is built in from the start. Building a hunt around unexpected image sources any pod running an image from a registry that isn't on your organization's approved list closes a gap that pure vulnerability scanning leaves wide open.



## Container escape attempts require watching the host layer, not just the container
The most severe container compromise scenario is escape an attacker breaking out of container isolation to gain access to the underlying host, which then potentially exposes every other workload running on that node. Escape techniques frequently involve privileged container configurations, host filesystem mounts, or kernel exploits, and the hunting signals live partly in the container's configuration (was it run with unnecessary privileged flags or excessive host mounts in the first place) and partly in host-level telemetry showing unexpected process activity originating from container namespaces.



Auditing which workloads in your cluster are actually running with privileged mode, host network access, or broad host path mounts is worth doing as a standing hygiene exercise independent of active hunting, because a huge share of container escape risk comes from configurations that were never necessary in the first place, granted early in a project's life for convenience and never revisited.



## Getting the fundamentals of visibility in place before hunting seriously
The honest starting point for a lot of organizations here isn't advanced hunting technique it's confirming basic visibility actually exists. Is API server audit logging turned on and retained somewhere durable. Is runtime security tooling deployed across the fleet or just a handful of pilot namespaces. Are container images actually being scanned and their provenance tracked. Container hunting without this foundation in place is trying to hunt in the dark, and a lot of organizations are further behind here than they'd like to admit.
