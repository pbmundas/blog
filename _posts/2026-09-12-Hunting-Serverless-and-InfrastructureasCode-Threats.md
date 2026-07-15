---
title: "Hunting Serverless and Infrastructure-as-Code Threats"
date: 2026-09-12 12:00:00 +0530
categories: [Threat Hunting, Cloud Security]
tags: [Serverless]
description: Serverless functions and IaC templates create attack surfaces most hunting programs haven't caught up to yet. Here's where to start.
---



![Serverless and infrastructure-as-code hunting across identity changes deployments and runtime behavior](/assets/img/threat-hunting/cloud-control-plane.svg)



A Lambda function can exist, execute maliciously, and disappear entirely in under a second. There's no host to image, no persistent process to catch mid-execution, sometimes not even a meaningful gap between "function invoked" and "function terminated" for an analyst to intervene in. Serverless architecture didn't just change how applications get built it fundamentally changed what "the endpoint" even means for hunting purposes, and a lot of hunting programs built around the assumption of persistent, investigable infrastructure haven't fully caught up.



Infrastructure-as-code adds a related but distinct problem: the attack surface shifts partly into the code and templates that define infrastructure before it's ever deployed, which means some of the most consequential security decisions in a cloud environment now happen in a Git repository rather than in the running infrastructure itself.



## Function invocation logging is the only forensic record you'll get
Since a serverless function's runtime environment is genuinely ephemeral potentially recycled or destroyed within moments of execution completing the invocation logs (CloudWatch Logs for Lambda, Application Insights for Azure Functions, Cloud Logging for Cloud Functions) are frequently the only forensic evidence that will ever exist for a given execution. This makes comprehensive, properly retained function logging a genuine prerequisite for any serverless hunting capability, not an optional enhancement.



The hunt itself focuses on anomalous invocation patterns: a function invoked far more frequently than its normal baseline, a function invoked with unusual input parameters that don't match its expected trigger sources, or execution duration that deviates significantly from historical norms a function that normally completes in 200 milliseconds suddenly running for the full timeout window is worth investigating, because that's consistent with either a performance problem or something unexpected happening inside the execution that's taking meaningfully longer than the function's normal logic should require.



## IAM permissions attached to functions deserve the same scrutiny as any other identity
Serverless functions run with an execution role carrying whatever permissions were assigned, and the same over-permissioning problem that shows up everywhere else in cloud IAM shows up here too, often worse functions get built quickly, permissions get granted broadly to avoid debugging access-denied errors during development, and nobody revisits the scope once the function's working in production. A function that only needs to read from one specific S3 bucket but was granted broad S3 read/write access across the account is carrying risk disproportionate to what it actually needs, and if that function is ever compromised through a code vulnerability, the blast radius is exactly as large as the over-permissioned role allows.



Auditing function execution roles against actual usage what API calls does this function's logs show it genuinely making versus what its IAM policy permits surfaces this gap directly, and it's worth treating as a standing hygiene exercise the same way over-permissioned container workloads are worth auditing in the Kubernetes context.



## Dependency and package compromise is a growing entry point specifically for serverless
Serverless functions frequently pull in third-party packages and layers, and a compromised dependency a malicious update to an npm package, say, or a tampered Lambda layer shared across multiple functions can affect every function using it simultaneously, all without any code change to the function's own logic that a code review would catch. This is a supply chain problem structurally similar to the container image provenance issue covered in the previous post, just expressed through package dependencies instead of container images.



Hunting here leans on the same principle: know what packages and layers your functions actually depend on, monitor for unexpected changes to those dependencies, and treat any function suddenly making network calls or API requests that its documented functionality doesn't explain as worth investigating, because that's often the first observable sign of a compromised dependency doing something the function's original developer never intended.



## Infrastructure-as-code hunting happens before deployment, in the repository itself
This is the piece that genuinely doesn't map onto any hunting discipline covered elsewhere in this series, because the "hunt" partly happens in source control rather than in running infrastructure. Terraform, CloudFormation, and similar IaC templates define security-critical configuration IAM policies, network rules, encryption settings and a malicious or accidentally over-permissive change to a template can introduce vulnerabilities that get deployed automatically the moment the pipeline runs, without any human ever reviewing the actual resulting cloud configuration directly.



Scanning IaC templates for risky patterns before deployment overly broad IAM policy statements, security group rules opening management ports to the internet, disabled encryption settings using tools built for this purpose catches a lot of this before it ever reaches production. But hunting-wise, the more interesting angle is watching for drift: infrastructure that's actually deployed and running that doesn't match what the current IaC templates define, which suggests either an out-of-band manual change (a common and often benign occurrence, but worth knowing about) or, in a worse case, an attacker directly modifying live infrastructure to bypass the change-controlled IaC pipeline entirely.



## CI/CD pipeline compromise threatens everything downstream at once
Both serverless deployment and IaC changes typically flow through a CI/CD pipeline, which makes that pipeline itself an extremely high-value target compromise the pipeline's credentials and an attacker can potentially push malicious infrastructure changes or function code that gets deployed with full legitimate authority, bypassing every other control covered above. Hunting for unusual pipeline activity deployments outside normal release schedules, pipeline configuration changes, or credentials used from outside the expected CI/CD infrastructure deserves to be treated as a Tier 0 hunting priority given how much downstream blast radius a compromised pipeline actually represents.



## Accepting that this is genuinely still-developing territory
Worth being honest about: tooling and established best practice for serverless and IaC hunting specifically are less mature than almost anything else covered in this series, and a lot of organizations are still figuring out what "good" looks like here in real time. That's not a reason to skip building capability it's a reason to start now, with the fundamentals of logging, permission auditing, and drift detection, rather than waiting for the discipline to fully mature before engaging with it.
