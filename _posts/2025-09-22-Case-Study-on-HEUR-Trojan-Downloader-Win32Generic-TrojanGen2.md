---
layout: post
title: "Case Study on HEUR:Trojan-Downloader.Win32.Generic (Trojan.Gen.2) "
date: 2025-09-22 13:40:00 +0530
categories: threat-investigation
---

### Case Study on HEUR:Trojan-Downloader.Win32.Generic (Trojan.Gen.2)

### Observation:

A **Malware/Trojan** Process was observed on the system **USR100.LOREM.LOCAL**. Below is the summary:

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| Risk | Monitoring Activity | RSC | Incident / Alert | Comments |
| **Critical** | Threats |  | Suspected Malicious process **384855e37b43fe3d3524b3af1b963ff4b0bba6ab.exe** (**Installer.exe**-**Process ID: 14540**) which has a **Virustotal** score of [**13/68**](https://www.virustotal.com/#/file/36452349fa2c0a511653119f769a9c1b2216d3304b09bd2df5ff0110213efbb3/detection) was observed on the system **USR100.LOREM.LOCAL** It is categorized as [**Trojan.Gen.2**](https://www.symantec.com/security_response/writeup.jsp?docid=2011-082216-3542-99) by **Symantec** and [**HEUR:Trojan-Downloader.Win32.Generic**](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/) by **Kaspersky** and is downloaded using **chrome.exe** (**Process ID: 4224**) by the user **user100.**  The process launched multiple unknown processes including **Bowsetup.exe (Process ID’s: 15492, 15712 and 15732)** which was found communicating to multiple bad reputed external IP addresses including **Botnet command and control center** [**52.206.6.222**](https://exchange.xforce.ibmcloud.com/ip/52.206.6.222) **(United States).** | **References:** [LINK1](http://www.toptenreviews.com/software/articles/how-to-remove-trojan.gen.2/) [LINK2](https://www.solvusoft.com/en/malware/trojans/trojan-gen-2/) [LINK3](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/) [LINK4](http://www.fixpcyourself.com/removal-of-heur-trojan-win32-generic-virus/)  **Note:**   1. The process was found installing adware/Spyware/unknown processes and DLL’s: RKSetup.exe (Adware/Spyware: [LINK1](https://forums.malwarebytes.com/topic/183518-removal-instructions-for-relevantknowledge/) [LINK2](https://forums.malwarebytes.com/topic/183518-removal-instructions-for-relevantknowledge/)) , InstallHope.exe, nsDialogs.dll (Part of heuristic: [LINK1](http://greatis.com/appdata/d/n/nsdialogs.dll.htm) [LINK2](http://virusbase.en.free-anti-spy.com/nsdialogs.dll/caa5s.php)), md5dll.dll (Part of RDN/Downloader/Grinidou: [LINK1](https://home.mcafee.com/virusinfo/virusprofile.aspx?key=3350322#none) [LINK2](http://software.sonicwall.com/applications/gav/index.asp?ev=v&v_id=4230)), Fusion.dll (PUA), Dialogs.dll, inetc.dll, System.dll (Part of Troj/Agent: [LINK1](https://file-intelligence.comodo.com/windows-process-virus-malware/dll/System) [LINK2](https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Troj~Agent-ALWD/detailed-analysis.aspx)), Banner.dll (Part of Adware: [LINK1](https://home.mcafee.com/virusinfo/virusprofile.aspx?key=9190874) [LINK2](https://home.mcafee.com/virusinfo/virusprofile.aspx?key=9190874)), INetC2.dll (Part of Generic/Lollipop: [LINK1](https://home.mcafee.com/virusinfo/virusprofile.aspx?key=635173) [LINK2](https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Lollipop/detailed-analysis.aspx)),fUtil.dll 2. [Trojan.Gen.2](https://www.symantec.com/security_response/writeup.jsp?docid=2011-082216-3542-99) and [HEUR:Trojan-Downloader.Win32.Generic](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/) processes are capable of doing the multiple activities   **Enhanced Incident Response (IR) Recommendations:**  Building on the initial actions, follow a structured IR process based on NIST guidelines for malware incidents:  1. **Preparation/Identification**: Confirm the incident scope by reviewing logs (e.g., Event IDs 3221, 3517) and isolating indicators like the MD5 hash (abee886adb40df7162d90f7a5b0201db). Use tools like VirusTotal to verify file maliciousness.  2. **Containment**: Immediately isolate the affected system (USR100.LOREM.LOCAL) from the network to prevent lateral movement or further downloads. Quarantine suspicious processes (e.g., BowSetup.exe) and block outbound traffic to known bad IPs (e.g., 52.206.6.222).  3. **Eradication**: Boot into Safe Mode and run full scans with multiple tools:  - Malwarebytes: Download from official site, scan, quarantine threats, and restart.  - HitmanPro: Perform a system scan and activate free trial for removal.  - ESET Online Scanner: Enable detection of potentially unwanted applications and clean remnants.  - AdwCleaner: Reset browser policies and remove adware injections.  4. **Recovery**: Restore from clean backups, change user credentials (e.g., for User100), and monitor for re-infection. Reconnect the system only after verification.  5. **Post-Incident** **Activity**: Conduct a root cause analysis (e.g., how Installer.exe was downloaded via Chrome) and update policies (e.g., restrict downloads).  **SOC Analyst Perspective:**  - Monitor for heuristic detections like HEUR:Trojan-Downloader.Win32.Generic in SIEM tools (e.g., unusual process creations via Event ID 3221).  - Set alerts for connections to high-risk IPs (e.g., AWS-hosted C2 like 52.206.6.222) and anomalous DLL loads (e.g., nsDialogs.dll).  - Correlate events across endpoints to detect patterns like adware installation leading to data exfiltration. |

### System involved:

**USR100.LOREM.LOCAL** (Workstation)

**Process Involved:**

1. **Chrome.exe**
2. **Bowsetup.exe**
3. **RKSetup.exe**
4. **InstallHope.exe**
5. **nsDialogs.dll**
6. **md5dll.dll**
7. **Fusion.dll**
8. **Dialogs.dll**
9. **inetc.dll**
10. **System.dll**
11. **Banner.dll**
12. **INetC2.dll**
13. **fUtil.dll**

**User Involved:**

**User100**

**Explanation:**

The threat is categorized as [**Trojan.Gen.2**](https://www.symantec.com/security_response/writeup.jsp?docid=2011-082216-3542-99) by **Symantec** and [**HEUR:Trojan-Downloader.Win32.Generic**](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/) by **Kaspersky.** This is basically Trojan downloader and was observed in the system **USR100.LOREM.LOCAL** (Workstation) by user **User100.**

Trojan.Gen.2 is a generic detection for many individual but varied Trojans for which specific definitions have not been created. A generic detection is used because it protects against many Trojans that share similar characteristics. Trojan horse programs masquerade as applications or files that entice a user to open it.

While most Trojans only execute their own malicious code, some Trojans may perform the actions of the file they pretend to be, but then they execute their own malicious code on the compromised computer.

Trojans arrive on to compromised computers in a variety of ways like spammed as an email attachment or a link in an email, file or link in an instant messaging client.

Another means of arrival includes a method called drive-by downloads. A drive-by download occurs when a user goes to a website that is either legitimate, but compromised and exploited or malicious by design. The download occurs surreptitiously without the user's knowledge.

Finally, a Trojan horse program can be dropped or downloaded by other malicious software or by legitimate programs that have been compromised or exploited on the compromised computer.

Once it is executed on the compromised computer, a Trojan horse program may create files and registry entries. It may copy itself to various locations. It may start a service or inject itself into processes and then carry out its primary functions.

Trojans can perform a large variety of actions. Some Trojan actions that are most commonly seen include:

1. Distributed Denial of Service
2. Downloading files
3. Dropping additional malware
4. Disabling security-related programs
5. Opening a back door
6. Stealing confidential and financial information

[**HEUR: Trojan-Downloader.Win32. Generic**](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/)is a heuristic detection designed to generically detect a *Trojan downloader*.

A typical behavior for Trojans like [**HEUR: Trojan-Downloader.Win32. Generic**](https://malwaretips.com/blogs/heur-trojan-win32-generic-virus/)is one or all of the following:

* Download and install other malware.
* Use your computer for click fraud.
* Record your keystrokes and the sites you visit.
* Send information about your PC, including usernames and browsing history, to a remote malicious hacker.
* Give a remote malicious hacker access to your PC.
* Advertising banners are injected with the web pages that you are visiting.
* Random web page text is turned into hyperlinks.
* Browser popups appear which recommend fake updates or other software.

**MITRE ATT&CK Mapping:** The behaviors observed map to the following MITRE ATT&CK techniques (inferred from the malware's generic downloader nature and specific actions like process injection, C2 communication, and data theft):

|  |  |  |  |
| --- | --- | --- | --- |
| Technique ID | Technique Name | Description | Mapping to Incident |
| T1189 | Drive-by Compromise | Adversaries compromise websites to exploit users visiting them, leading to malware downloads. | Matches the drive-by download method via Chrome.exe downloading Installer.exe. |
| T1204.002 | User Execution: Malicious File | Relies on user opening/executing a malicious file (e.g., via social engineering). | User100 executed Installer.exe, launching BowSetup.exe. |
| T1055 | Process Injection | Injects code into processes (e.g., loading DLLs like nsDialogs.dll, md5dll.dll). | BowSetup.exe loaded multiple suspicious DLLs for evasion and execution. |
| T1105 | Ingress Tool Transfer | Downloads tools or payloads from external sources. | Installer.exe downloaded additional malware like RKSetup.exe and InstallHope.exe. |
| T1071 | Application Layer Protocol | Uses HTTP/HTTPS for C2 communication. | BowSetup.exe connected to C2 IPs (e.g., 52.206.6.222 over port 80). |
| T1056 | Input Capture | Captures keystrokes or user input. | Heuristic detection includes keylogging capabilities. |
| T1005 | Data from Local System | Collects and exfiltrates system data (e.g., usernames, browsing history). | Sends PC info to remote hackers. |
| T1041 | Exfiltration Over C2 Channel | Exfiltrates data over the same channel used for C2. | Potential data theft via C2 connections. |

These mappings help in threat hunting and aligning defenses (source: MITRE ATT&CK framework, adapted to observed behaviors).

**Scenario:**

The attack was happened in between the time interval **FEB 15 07 10 PM** and **07 20 PM.** Alert was generated when the user tried to download a process **Installer.exe** from chrome which launched another process **Bowsetup.exe**. This process loaded many **dlls** and tried to communicate **CnC**.

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| Log Time | Event Id | Event User | Computer | Event Description |
| 2/15/2018 7:18:03 PM | 8005 | user100 | USR100.LOREM.LOCAL | An unknown MD5 hash has been detected. Hash: ABEE886ADB40DF7162D90F7A5B0201DB System: USR100.LOREM.LOCAL Time: 2018-02-15 19:12:23 Image File Name: C:\Users\user100\Downloads\Installer.exe User: DMN\user100 File Name: Installer.exe Creator Process Name: chrome.exe Creator Image File Name: C:\Program Files (x86)\Google\Chrome\Application\chrome.exe File Version: 1.0.1.9 File Description: Bow Setup Product Name: BowSetup Product Version: 1.0.1.9 Process Command Line: "C:\Users\user100\Downloads\Installer.exe" File Size: 65592(Bytes) Last Modified Time: 2018-02-15T19:12:17Z Signer: SIMMERSON SERVICES LIMITED Counter Signer: Symantec Time Stamping Services Signer - G4 Counter Signed On: 2018-01-29T13:19:53Z |
| 2/15/2018 7:18:02 PM | 2040 | user100 | USR100.LOREM.LOCAL | New activity found: Rule Name: Process MD5 Hash Activity System: USR100.LOREM.LOCAL Time: 2018-02-15 19:12:23 Hash: ABEE886ADB40DF7162D90F7A5B0201DB Image File Name: C:\Users\user100\Downloads\Installer.exe User: DMN\user100  Source Event: Id: 3221 Source:  Description: A new process has been created. Process Name: Installer.exe Image File Name: C:\Users\user100\Downloads\Installer.exe Account Name: user100 Account Domain: DMN New Process ID: 14540 Creator Process ID: 4224 Creator Process Name: chrome.exe Creator Image File Name: C:\Program Files (x86)\Google\Chrome\Application\chrome.exe System Name: USR100.LOREM.LOCAL File Version: 1.0.1.9 File Description: Bow Setup Product Name: BowSetup Product Version: 1.0.1.9 Process Command Line: "C:\Users\user100\Downloads\Installer.exe"  File Size: 65592(Bytes) Last Modified Time: 2018-02-15T19:12:17Z Signed: Yes Signer: SIMMERSON SERVICES LIMITED Signed On: 2018-01-29T13:19:53Z Counter Signed: Yes Counter Signer: Symantec Time Stamping Services Signer - G4 Counter Signed On: 2018-01-29T13:19:53Z Session ID: 1 UserSid: S-1-5-21-171733894-448721725-2163998464-2779 Token Elevation Type: TokenElevationTypeLimited(3) LogonId: 0x140d86 Token Integrity Level: Medium Hash (MD5): abee886adb40df7162d90f7a5b0201db |

**Installer Launching Unknown process**

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| **Log Time** | **Event Id** | **Event User** | **Computer** | **Event Description** |
| 2/15/2018 7:12:30 PM | 3221 | user100 | USR100.LOREM.LOCAL | A new process has been created. Process Name: BowSetup.exe Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN New Process ID: 15712 Creator Process ID: 15492 Creator Process Name: Installer.exe Creator Image File Name: C:\Users\user100\Downloads\Installer.exe System Name: USR100.LOREM.LOCAL File Version: 3.2.14.1 File Description: The PriMeApp Software Product Name: PriMeApp Product Version: N/A Process Command Line: "C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe" /path="C:\Users\user100\Downloads\Installer.exe" File Size: 2585488(Bytes) Last Modified Time: 2018-02-15T19:12:27Z Signed: Yes Signer: App Science Corporation Signed On: 2018-02-14T08:16:22Z Counter Signed: Yes Counter Signer: Symantec Time Stamping Services Signer - G4 Counter Signed On: 2018-02-14T08:16:22Z Session ID: 1 UserSid: S-1-5-21-171733894-448721725-2163998464-2779 Token Elevation Type: N/A LogonId: N/A Token Integrity Level: N/A Hash (MD5): 050d4b15969c5132a1d37d1a9951e9b2 |
| 2/15/2018 7:12:30 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: Installer.exe Process Image File Name: C:\Users\user100\Downloads\Installer.exe Account Name: user100 Account Domain: DMN Process ID: 15492 System Name: USR100.LOREM.LOCAL Image Name: BowSetup.exe Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe File Version: 3.2.14.1 File Description: The PriMeApp Software Product Name: PriMeApp Product Version: N/A File Size: 2585488(Bytes) Last Modified Time: 2018-02-15T19:12:27Z Signed: Yes Signer: App Science Corporation Signed On: 2018-02-14T08:16:22Z Counter Signed: Yes Counter Signer: Symantec Time Stamping Services Signer - G4 Hash (MD5): 050d4b15969c5132a1d37d1a9951e9b2 |

Unknown process Launching Bowsetup

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| **Log Time** | **Event Id** | **Event User** | **Computer** | **Event Description** |
| 2/15/2018 7:18:03 PM | 2040 | user100 | USR100.LOREM.LOCAL | New activity found: Application: BOWSETUP.EXE Rule Name: Windows Applications Activity System: USR100.LOREM.LOCAL Time: 2018-02-15 19:12:30  Source Event: Id: 3221 Source:  Description: A new process has been created. Process Name: BowSetup.exe Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN New Process ID: 15712 Creator Process ID: 15492 Creator Process Name: Installer.exe Creator Image File Name: C:\Users\user100\Downloads\Installer.exe System Name: USR100.LOREM.LOCAL File Version: 3.2.14.1 File Description: The PriMeApp Software Product Name: PriMeApp Product Version: N/A Process Command Line: "C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe" /path="C:\Users\user100\Downloads\Installer.exe" File Size: 2585488(Bytes) Last Modified Time: 2018-02-15T19:12:27Z Signed: Yes Signer: App Science Corporation Signed On: 2018-02-14T08:16:22Z Counter Signed: Yes Counter Signer: Symantec Time Stamping Services Signer - G4 Counter Signed On: 2018-02-14T08:16:22Z Session ID: 1 UserSid: S-1-5-21-171733894-448721725-2163998464-2779 Token Elevation Type: N/A LogonId: N/A Token Integrity Level: N/A Hash (MD5): 050d4b15969c5132a1d37d1a9951e9b2 |

Bowsetup loading DLLS and process

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| **Log Time** | **Event Id** | **Event User** | **Computer** | **Event Description** |
| 2/15/2018 7:13:37 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: full.dll Image File Name: C:\Users\user100\AppData\Local\Temp\nsjE5E2.tmp\full.dll File Version: 2, 0, 6, 1 File Description: duke software Product Name: duke software Product Version: 1, 2, 0, 1 File Size: 868864(Bytes) Last Modified Time: 2018-02-15T19:13:35Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): c644058d03e6b7b1ea49bc021d8d257d |
| 2/15/2018 7:12:46 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: dxtmsft.dll Image File Name: C:\Windows\SysWOW64\dxtmsft.dll File Version: 11.00.9600.18894  File Description: DirectX Media -- Image DirectX Transforms Product Name: Internet Explorer Product Version: 11.00.9600.18894 File Size: 416256(Bytes) Last Modified Time: 2018-02-01T14:23:57Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): cb1e60b2be7f125849b8060f2227da14 |
| 2/15/2018 7:12:46 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: dxtrans.dll Image File Name: C:\Windows\SysWOW64\dxtrans.dll File Version: 11.00.9600.18894  File Description: DirectX Media -- DirectX Transform Core Product Name: Internet Explorer Product Version: 11.00.9600.18894 File Size: 279040(Bytes) Last Modified Time: 2018-02-01T14:23:57Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): 49ae7fce7f6e49ade2404c3919e71fbe |
| 2/15/2018 7:12:45 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: sqlite3.dll Image File Name: C:\Users\user100\AppData\Local\Temp\NS1522~1\03967E~1\sqlite3.dll File Version: 3.16.2 File Description: SQLite is a software library that implements a self-contained, serverless, zero-configuration, transactional SQL database engine. Product Name: SQLite Product Version: 3.16.2 File Size: 488334(Bytes) Last Modified Time: 2018-02-15T19:12:35Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): 687cfb29a2ac64018edc845c65e19bc5 |
| 2/15/2018 7:12:43 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: nsDialogs.dll Image File Name: C:\Users\user100\AppData\Local\Temp\nsjE5E2.tmp\nsDialogs.dll File Version:  File Description:  Product Name:  Product Version:  File Size: 9728(Bytes) Last Modified Time: 2018-02-15T19:12:32Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): f832e4279c8ff9029b94027803e10e1b |
| 2/15/2018 7:12:35 PM | 3517 | user100 | USR100.LOREM.LOCAL | Image loaded by a process. Process Name: BowSetup.exe Process Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe Account Name: user100 Account Domain: DMN Process ID: 15732 System Name: USR100.LOREM.LOCAL Image Name: md5dll.dll Image File Name: C:\Users\user100\AppData\Local\Temp\nsjE5E2.tmp\md5dll.dll File Version: 0.5.0-0 File Description: MD5 message digest algorithm Product Name: md5dll Product Version: 0.5.0-0 File Size: 6656(Bytes) Last Modified Time: 2018-02-15T19:12:30Z Signed: No Signer: N/A Signed On: N/A Counter Signed: No Counter Signer: N/A Hash (MD5): 0745ff646f5af1f1cdd784c06f40fce9 |
| 2/15/2018 7:14:52 PM | 3221 | user100 | USR100.LOREM.LOCAL | A new process has been created. Process Name: pu.exe Image File Name: C:\Users\user100\AppData\Local\PriMeApp\pu.exe Account Name: user100 Account Domain: DMN New Process ID: 16140 Creator Process ID: 15732 Creator Process Name: BowSetup.exe Creator Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe System Name: USR100.LOREM.LOCAL File Version: 2.4.0.0 File Description: PrUpdater Product Name: PrUpdater Product Version: 2.4.0.0 Process Command Line: "C:\Users\user100\AppData\Local\PriMeApp\pu.exe" /S File Size: 1238608(Bytes) Last Modified Time: 2018-02-15T19:14:50Z Signed: Yes Signer: Prime Soft Inc Signed On: 2018-02-09T18:13:48Z Counter Signed: Yes Counter Signer: COMODO SHA-1 Time Stamping Signer Counter Signed On: 2018-02-09T18:13:48Z Session ID: 1 UserSid: S-1-5-21-171733894-448721725-2163998464-2779 Token Elevation Type: TokenElevationTypeFull(2) LogonId: 0x140d1b Token Integrity Level: High Hash (MD5): 002e35ac856ef906c8109032e43500b8 |
| 2/15/2018 7:13:50 PM | 3221 | user100 | USR100.LOREM.LOCAL | A new process has been created. Process Name: RKSetup.exe Image File Name: C:\Users\user100\AppData\Local\PriMeApp\RKSetup.exe Account Name: user100 Account Domain: DMN New Process ID: 15004 Creator Process ID: 15732 Creator Process Name: BowSetup.exe Creator Image File Name: C:\Users\user100\AppData\Roaming\BowSetupShot\BowSetup.exe System Name: USR100.LOREM.LOCAL File Version: 2.0.7.33 File Description: RelevKnowledge Software Installer Product Name: RelevKnowledge Setup Product Version: N/A Process Command Line: "C:\Users\user100\AppData\Local\PriMeApp\RKSetup.exe" /q=1350091235 /path=C:\Users\user100\AppData\Local\PriMeApp\PKZQZXZW File Size: 495496(Bytes) Last Modified Time: 2018-02-15T19:13:45Z Signed: Yes Signer: App Science Corporation Signed On: 2018-02-14T11:29:10Z Counter Signed: Yes Counter Signer: Symantec Time Stamping Services Signer - G4 Counter Signed On: 2018-02-14T11:29:10Z Session ID: 1 UserSid: S-1-5-21-171733894-448721725-2163998464-2779 Token Elevation Type: TokenElevationTypeFull(2) LogonId: 0x140d1b Token Integrity Level: High Hash (MD5): dc1c6ad1f1ab83e3bf41e6e8faab7e1d |

Bowsetup connecting Cnc

|  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LogTime | Type | Local Address | Local Hostname | Local Port | Remote Address | Remote Hostname | Remote Port |
| 2/15/2018 7:14:53 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61893 | 52.206.6.222 | ec2-52-206-6-222.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:14:51 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61891 | 104.25.94.105 | 104.25.94.105 | 443 |
| 2/15/2018 7:13:50 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61855 | 52.206.6.222 | ec2-52-206-6-222.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:13:50 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61856 | 52.206.6.222 | ec2-52-206-6-222.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:13:40 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61842 | 104.25.93.105 | 104.25.93.105 | 80 |
| 2/15/2018 7:13:40 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61841 | 104.25.93.105 | 104.25.93.105 | 80 |
| 2/15/2018 7:13:40 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61844 | 104.25.93.105 | 104.25.93.105 | 80 |
| 2/15/2018 7:13:39 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61840 | 104.25.93.105 | 104.25.93.105 | 80 |
| 2/15/2018 7:13:39 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61843 | 104.25.93.105 | 104.25.93.105 | 80 |
| 2/15/2018 7:13:37 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61839 | 54.243.250.185 | ec2-54-243-250-185.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61812 | 192.96.201.162 | 192.96.201.162 | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61811 | 46.166.187.59 | 46.166.187.59 | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61810 | 46.166.187.59 | 46.166.187.59 | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61807 | 185.59.222.146 | unn-185-59-222-146.10gbps.io | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61808 | 185.59.222.146 | unn-185-59-222-146.10gbps.io | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61815 | 52.206.6.222 | ec2-52-206-6-222.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:12:46 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61813 | 192.96.201.162 | 192.96.201.162 | 80 |
| 2/15/2018 7:12:43 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61802 | 104.25.94.105 | 104.25.94.105 | 443 |
| 2/15/2018 7:12:42 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61797 | 52.218.200.24 | s3-us-west-2.amazonaws.com | 443 |
| 2/15/2018 7:12:42 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61793 | 52.206.6.222 | ec2-52-206-6-222.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:12:42 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61795 | 35.164.105.161 | ec2-35-164-105-161.us-west-2.compute.amazonaws.com | 80 |
| 2/15/2018 7:12:42 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61800 | 54.243.250.185 | ec2-54-243-250-185.compute-1.amazonaws.com | 80 |
| 2/15/2018 7:12:35 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61789 | 104.25.94.105 | 104.25.94.105 | 443 |
| 2/15/2018 7:12:35 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61791 | 104.25.94.105 | 104.25.94.105 | 443 |
| 2/15/2018 7:12:34 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61788 | 72.21.91.29 | 72.21.91.29 | 80 |
| 2/15/2018 7:12:34 PM | TCP | 192.168.100.113 | USR100.LOREM.LOCAL | 61786 | 52.218.200.24 | s3-us-west-2.amazonaws.com | 443 |

### Lesson learnt:

AV, software patching and network scanners are available in most of the infrastructure, but it is imperative to have an additional level of logging and analysis to find vulnerabilities that go unnoticed in these traditional controls. Everyone should be updated with emerging Threat/Attack/Vulnerability/Exploits.
