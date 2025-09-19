---
layout: post
title: "Top Resources for Attack Simulation Logs: A Blue Teamer's Guide to Enhancing Threat Hunting Skills"
date: 2025-09-19 13:40:00 +0530
categories: threat-hunting threat-investigation soc resources
---

As a senior threat hunter, one of the biggest challenges is accessing high-quality, diverse logs from simulated attacks to refine detection strategies, test hypotheses, and train teams. Generating these logs in-house can be resource-intensive, requiring complex setups for attack emulation. Fortunately, the cybersecurity community has curated numerous reliable datasets from simulations, covering endpoint, network, application, cloud, and container environments. These come from trusted sources like academic institutions, security vendors, and open-source projects.

In this post, I'll curate a comprehensive list of these resources, drawing from reputable repositories and datasets. I'll categorize them by log type, explain their importance for blue teaming, and provide key details like formats, coverage, and access methods. This isn't exhaustive, but I've focused on avoiding duplicates and prioritizing downloadable, usable data from reliable origins (e.g., GitHub repos from established orgs, university labs, and security firms). Use these to baseline normal vs. malicious behavior, map to MITRE ATT&CK, and improve your hunting processes.

## Endpoint Logs from Attack Simulations

Endpoint logs are crucial for detecting host-based threats like malware persistence or lateral movement. These datasets help blue teams practice parsing Windows/Linux events, Sysmon data, and behavioral indicators.

- **Mordor Datasets (OTRF/Security-Datasets)**  
  Importance: Mordor provides pre-recorded security events from simulated adversarial techniques, enabling replay for detection development without live simulations. It's aligned with MITRE ATT&CK, making it ideal for hypothesis-driven hunting and validating EDR rules.  
  Details: Focuses on endpoint events (e.g., Windows Sysmon, Event Logs) in JSON format for easy consumption. Covers tactics like credential access and execution from groups like APT29. Download from GitHub: https://github.com/OTRF/mordor. Free, open-source, and portable for analysis in tools like Splunk or ELK.

- **Unified Host and Network Dataset (Los Alamos National Laboratory)**  
  Importance: This dataset blends real enterprise endpoint logs with simulated anomalies, helping blue teams identify insider threats or compromised hosts in large-scale environments.  
  Details: Includes Windows host event logs over 90 days, with authentication and process data. Formats: CSV/JSON. Access: https://csr.lanl.gov/data/2017.html. Reliable government-lab source, useful for baselining user behavior.

- **ADFA Intrusion Detection Datasets (UNSW Canberra)**  
  Importance: Tailored for host-based intrusion detection system (HIDS) evaluation, these simulate modern exploits on Linux/Windows, aiding in fine-tuning endpoint detections for zero-days.  
  Details: Contemporary Linux/Windows logs with attack vectors like exploits and backdoors. Formats: Not specified, but structured for ML/analysis. Download: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/.

- **Public Security Log Sharing Site**  
  Importance: Offers unsanitized logs from compromised systems, providing raw, real-world endpoint data for forensic training and threat hunting drills.  
  Details: Samples from systems/devices with evidence of compromise. Formats: Various raw logs. Access: http://log-sharing.dreamhosters.com/. Community-driven but reliable for educational use.

- **Aktaion2 Data**  
  Importance: Focuses on blending signals for intrusion detection, useful for endpoint hunting involving multiple behaviors like ransomware.  
  Details: Endpoint-focused datasets for ML models. Formats: Not specified. Download: https://github.com/jzadeh/aktaion2/tree/master/data.

- **OpTC Data (FiveDirections)**  
  Importance: Includes endpoint activity with red-team malware injections, perfect for testing EDR and hunting in mixed benign/malicious scenarios.  
  Details: Logs from ~500 endpoints, including Zeek data. Formats: Various. Download: https://github.com/FiveDirections/OpTC-data.

## Network Logs from Attack Simulations

Network logs (e.g., PCAPs, flows) are essential for spotting C2, exfiltration, or DDoS. These datasets allow blue teams to practice packet analysis and anomaly detection.

- **IoT-23 Dataset (Stratosphere IPS)**  
  Importance: Labeled IoT malware traffic helps detect botnets in edge networks, critical for blue teams defending hybrid environments.  
  Details: 20 malware + 3 benign captures; PCAP, Zeek conn.log with labels (e.g., DDoS, C&C). Covers Mirai, Torii, etc. Download: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/ (full 20GB or light 8.7GB).

- **CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)**  
  Importance: Comprehensive for IDS testing, with labeled flows from brute-force to infiltration, enabling network hunting benchmarks.  
  Details: PCAPs, system logs, CSV flows (80+ features). Seven scenarios including DDoS, web attacks. Access: AWS S3 sync via CLI.

- **CTU-13 Dataset (Stratosphere IPS)**  
  Importance: Botnet-focused with normal/background traffic, ideal for network-based anomaly hunting.  
  Details: 13 malware captures; PCAP/flows. Download: https://www.stratosphereips.org/datasets-ctu13/.

- **Malware Traffic Analysis PCAPs**  
  Importance: Real malware network traces for threat hunting exercises, sharpening skills in identifying suspicious traffic.  
  Details: PCAPs from 2013-2025, with samples. Access: https://www.malware-traffic-analysis.net/.

- **UNSW-NB15 Dataset (UNSW Canberra)**  
  Importance: Hybrid normal/attack traffic for ML-based detection, covering nine attack families.  
  Details: PCAPs/flows with fuzzers, exploits, etc. Download: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/.

- **NETRESEC PCAP Repository**  
  Importance: Diverse network captures for forensics, including SCADA/ICS attacks.  
  Details: PCAP files for malware, packet injection. Access: https://www.netresec.com/?page=PcapFiles.

## Application Logs from Attack Simulations

Application logs reveal web exploits, injections, or API abuses. These are key for hunting in app layers.

- **Synthetic Cybersecurity Logs for Anomaly Detection (Kaggle)**  
  Importance: Simulates HTTP logs for anomaly detection, helping blue teams spot app-level threats like injections.  
  Details: Features like timestamps, IPs; CSV format. Download: Kaggle.

- **ICS Attack Dataset From Railway Cyber Range (arXiv)**  
  Importance: Includes app logs from web attacks in industrial simulations.  
  Details: Logs + videos; formats vary. Access: https://arxiv.org/html/2507.01768v1.

- **VAST Challenge Datasets**  
  Importance: Includes app-related logs (e.g., firewall, IDS) from cyber exercises.  
  Details: Network status, IPS data; various formats. Access: http://vacommunity.org/VAST+Challenge+2013 (and 2012).

## Cloud Logs from Attack Simulations

Cloud logs cover IAM abuses, data exfil, etc., vital for multi-cloud hunting.

- **Splunk Attack Range**  
  Importance: Automates cloud attack simulations, generating logs for detection testing in AWS/Azure/GCP.  
  Details: Logs like CloudWatch, Azure Monitor; integrates with Splunk. GitHub: https://github.com/splunk/attack_range.

- **Stratus Red Team (DataDog)**  
  Importance: Granular cloud adversary emulation, producing audit logs for threat detection training.  
  Details: Supports AWS (extensible to Azure); self-contained attacks. GitHub: https://github.com/DataDog/stratus-red-team.

## Container and Kubernetes Logs from Attack Simulations

Container logs are emerging; focus on runtime threats like escapes.

- **Awesome Kubernetes Threat Detection (GitHub)**  
  Importance: Curates tools/resources for K8s detection, including simulation logs from projects like Falco.  
  Details: Links to datasets/logs for pod escapes, crypto mining. GitHub: https://github.com/jatrost/awesome-kubernetes-threat-detection.

- **Kubernetes Attack Simulation Guide (DEF CON)**  
  Importance: Details logs from K8s components during attacks, for DFIR in containers.  
  Details: API server, kubelet logs; PDF with examples. Access: DEF CON resources.

## Cross-Category and Tooling Resources

- **Splunk Attack Data Repository**  
  Importance: Curated logs from various attacks, replayable for SIEM testing.  
  Details: Endpoint/network (Sysmon, Crowdstrike); YML/JSON. GitHub: https://github.com/splunk/attack_data.

- **Awesome Cybersecurity Datasets (GitHub)**  
  Importance: Master list for discovering more; ensures comprehensive coverage.  
  Details: Aggregates all types. GitHub: https://github.com/shramos/Awesome-Cybersecurity-Datasets.

- **Honeynet Project Challenges**  
  Importance: Multi-type logs (PCAP, malware) from forensics challenges.  
  Details: Various formats. Access: http://honeynet.org/challenges.

These resources can reduce your simulation efforts by 50-70% in my experience. Start with Mordor or CIC for quick wins, then scale to tools like Attack Range for custom logs. Always verify data integrity and cite sources in reports. If you have a specific focus (e.g., AWS), let me know for deeper dives!
