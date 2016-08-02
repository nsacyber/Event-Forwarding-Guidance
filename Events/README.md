# Windows Event Monitoring Guidance
## Recommended Events to Collect

### Account Usage
User account information can be collected and audited. Tracking local account usage can help detect Pass the Hash activity and other unauthorized account usage. Additional information such as remote desktop logins, users added to privileged groups, and account lockouts can also be tracked. User accounts being promoted to privileged groups should be audited very closely to ensure that users are in fact supposed to be in a privileged group. Unauthorized membership in privileged groups is a strong indicator that malicious activity has occurred.

Lockout events for domain accounts are generated on the domain controller whereas lockout events for local accounts are generated on the local computer.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Account Lockouts | 4740 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Account Login with Explicit Credentials | 4648 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Failed User Account Login | 4625 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Security-Enabled group Modification | 4735 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Successful User Account Login | 4624 | Informational | Security | Microsoft-Windows-Security-Auditing |
| User Added to Privileged Group | 4728, 4732, 4756 | Informational | Security | Microsoft-Windows-Security-Auditing |

### Application Crashes
Application crashes may warrant investigation to determine if the crash is malicious or benign. Categories of crashes include Blue Screen of Death (BSOD), Windows Error Reporting (WER), Application Crash and Application Hang events. If the organization is actively using the Microsoft Enhanced Mitigation Experience Toolkit (EMET), then EMET logs can also be collected.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| App Error | 1000 | Error | Application | Application Error |
| App Hang | 1002 | Error | Application | Application Hang |
| BSOD | 1001 | Error | System | Microsoft-Windows-WER-SystemErrorReporting |
| EMET | 1 | Warning | Application | EMET |
| EMET | 2 | Error | Application | EMET |
| WER | 1001 | Informational | Application | Windows Error Reporting |

### Application Whitelisting
Application whitelisting events should be collected to look for applications that have been blocked from execution. Any blocked applications could be malware or users trying to run unapproved software. Software Restriction Policies (SRP) is supported on Windows XP and above. The AppLocker feature is available for Windows 7 and above Enterprise and Ultimate editions only. Application Whitelisting events can be collected if SRP or AppLocker are actively being used on the network.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| AppLocker Block | 8003 | Error | Microsoft-Windows-AppLocker/EXE and DLL | Microsoft-Windows-AppLocker |
| AppLocker Block | 8004 | Warning | Microsoft-Windows-AppLocker/EXE and DLL | Microsoft-Windows-AppLocker |
| AppLocker Warning | 8006 | Error | Microsoft-Windows-AppLocker/MSI and Script | Microsoft-Windows-AppLocker |
| AppLocker Warning | 8007 | Warning | Microsoft-Windows-AppLocker/MSI and Script | Microsoft-Windows-AppLocker |
| SRP Block | 865, 866, 867, 868, 882 | Warning | Application | Microsoft-Windows-SoftwareRestrictionPolicies |

### Clearing Event Logs
It is unlikely that event log data would be cleared during normal operations and it is likely that a malicious attacker may try to cover their tracks by clearing an event log. When an event log gets cleared, it is suspicious. Centrally collecting events has the added benefit of making it much harder for an attacker to cover their tracks. Event forwarding permits sources to forward multiple copies of a collected event to multiple collectors thus enabling redundant event collection. Using a redundant event collection model can minimize the single point of failure risk.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Event Log was Cleared | 104 | Informational | System | Microsoft-Windows-Eventlog |
| Event Log was Cleared | 1102 | Informational | Security | Microsoft-Windows-Eventlog |

### External Media Detection
Detection of USB device (e.g., mass storage devices) usage is important in some environments, such as air gapped networks. This section attempts to take the proactive avenue to detect USB insertion at real-time. Event ID 43 only appears under certain circumstances. The following events and event logs are only available in Windows 8 and above.

Microsoft-Windows-USB-USBHUB3-Analytic is not an event log per se; it is a trace session log that stores tracing events in an Event Trace Log (.etl) file. The events created by Microsoft-Windows-USB-USBHUB3 publisher are sent to a direct channel (i.e., Analytic log) and cannot be subscribed to for event collection. Administrators should seek an alternative method of collecting and analyzing this event (43).

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| New Device Information | 43 | Informational | Microsoft-Windows-USB-USBHUB3-Analytic | Microsoft-Windows-USB-USBHUB3 |
| New Mass Storage Installation | 400, 410 | Informational | Microsoft-Windows-Kernel-PnP/Device Configuration | Microsoft-Windows-Kernel-PnP |

### Group Policy Errors
Management of domain computers permits administrators to heighten the security and regulation of those machines with Group Policy. The inability to apply a policy due to a group policy error reduces the aforementioned benefits. An administrators should investigate these events immediately.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Generic Internal Error | 1126 | Error | System | Microsoft-Windows-GroupPolicy |
| Group Policy Application Failed due to Connectivity | 1129 | Error | System | Microsoft-Windows-GroupPolicy |
| Internal Error | 1125 | Error | System | Microsoft-Windows-GroupPolicy |

### Kernel Driver Signing
Introduction of kernel driver signing in the 64-bit version of Windows Vista significantly improves defenses against insertion of malicious drivers or activities in the kernel. Any indication of a protected driver being altered may indicate malicious activity or a disk error and warrants investigation.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Code Integrity Check | 3001, 3002, 3003, 3004, 3010, 3023 | Warning, Error | Microsoft-Windows-CodeIntegrity/Operational | Microsoft-Windows-CodeIntegrity |
| Detected an invalid image hash of a file | 5038 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Detected an invalid page hash of an image file | 6281 | Informational | Security | Microsoft-Windows-Security-Auditing |
| Failed Kernel Driver Loading | 219 | Warning | System | Microsoft-Windows-Kernel-PnP |

### Mobile Device Activities
Wireless devices are ubiquitious and the need to record an enterprise's wireless device activities may be critical. A wireless device could become compromised while traveling between different networks, regardless of the protocol used for communication (e.g., 802.11 or Bluetooth). Therefore, the tracking of which networks mobile devices are entering and exiting is useful to prevent further compromises. The creation frequency of the following events depend on how often the device disconnects and reconnects to a wireless network. Each event below provides mostly similar information with the exception that additional fields have been added to certain events.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Disconnect from Wireless connection | 8003 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Network Connection and Disconnection Status (Wired and Wireless) | 10000, 10001 | Informational | Microsoft-Windows-NetworkProfile/Operational | Microsoft-Windows-NetworkProfile |
| Starting a Wireless connection | 8000, 8011 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Successfully connected to a Wireless connection | 8001 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Association Status | 11000, 11001 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Association Status | 11002 | Error | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Authentication Started and Failed | 12011, 12012 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Authentication Started and Failed | 12013 | Error | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Connection Failed | 8002 | Error | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Security Started, Stopped, Successful, or Failed | 11004, 11005 | Informational | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |
| Wireless Security Started, Stopped, Successful, or Failed | 11010, 11006 | Error | Microsoft-Windows-WLAN-AutoConfig/Operational | Microsoft-Windows-WLAN-AutoConfig |

### Pass the Hash Detection
Tracking user accounts for detecting Pass the Hash (PtH) requires creating a custom view with XML to configure more advanced filtering options. The event query language is based on XPath. The recommended **QueryList** below is limited in detecting PtH attacks. These queries focus on discovering lateral movement by an attacker using local accounts that are not part of a domain. The **QueryList** captures events that show a local account attempting to connect remotely to another machine not part of the domain. This event is a rarity so any occurrence should be treated as suspicious.

These XPath queries below are used for the Event Viewer's **Custom Views**.

The successful use of PtH for lateral movement between workstations would trigger event ID 4624, with an event level of Informational, from the Security log. This behavior would be a **LogonType** of 3 using NTLM authentication where it is not a domain logon and not the ANONYMOUS LOGON account. To clearly summarize the event that is being collected, see event 4624 below.

In the **QueryList** below, substitute the <DOMAIN NAME> section with the desired domain name.

A failed logon attempt when trying to move laterally using PtH would trigger an event ID 4625. This would have a **LogonType** of 3 using NTLM authentication where it is not a domain logon and not the ANONYMOUS LOGON account. To clearly summarize the event that is being collected, see event 4625 below.

```xml
<QueryList>
  <Query Id="0" Path="Forwarded Events">
    <Select Path="ForwardedEvents">
      *[System[(Level=4 or Level=0) and (EventID=4624)]]
      and
      *[EventData[Data[@Name='LogonType'] and (Data='3')]]
      and
      *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
      and
      *[EventData[Data[@Name='TargetDomainName'] != '<DOMAIN NAME>']]
    </Select>
  </Query>
</QueryList>
<QueryList>
  <Query Id="0" Path="Forwarded Events">
    <Select Path="ForwardedEvents">
      *[System[(Level=4 or Level=0) and (EventID=4625)]]
      and
      *[EventData[Data[@Name='AuthenticationPackageName'] and (Data='3')]]
      and
      *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
      and
      *[EventData[Data[@Name='TargetDomainName'] != '<DOMAIN NAME>']]
    </Select>
  </Query>
</QueryList>
```
| Event ID | Log | Level | LogonType | Authentication Pkg Name |
| --- | --- | --- | --- | --- |
| 4624 | Security | Information | 3 | NTLM |
| 4625 | Security | Information | 3 | NTLM |

### Printing Services
Document printing is essential for daily operations in many environments. The vast amount of printing requests increases the difficulty in tracking and identifying which document was printed and by whom. Documents forwarded to a printer for processing can be recorded for logging purposes in multiple ways. Each printing job can be logged either by a printing server, the printer itself, or the requesting machine. The logging of these activities permits early detection of printing certain documents. The following event is generated on the client machine requesting to print a document. This event should be treated as a historical record or an additional piece of evidence rather than an auditing record of printing jobs.

This operational log is disabled by default and requires the log to be enabled to capture this event.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Printing Document | 307 | Informational | Microsoft-Windows-PrintService/Operational | Microsoft-Windows-PrintService |

### Remote Desktop Logon Detection
Remote Desktop account activity events are not easily identifiable using the Event Viewer GUI. When an account remotely connects to a client, a generic successful logon event is created. A custom **Query Filter** can aid in clarifying the type of logon that was performed. The query below shows logins using Remote Desktop. Remote Desktop activity should be monitored since only certain administrators should be using it, and they should be from a limited set of management workstations. Any Remote Desktop logins outside of expected activity should be investigated.

The XPath queries below are used for the Event Viewer's **Custom Views**. Event ID 4624 and Event ID 4634 respecively indicate when a user has logged on and logged off with RDP. A LogonType with the value of 10 indicates a Remote Interactive logon.

```xml
<QueryList>
  <Query Id="0" Path="ForwardedEvent">
    <Select Path="ForwardedEvents">
    <!-- Collects Logon and Logoffs in RDP -->
    <!-- Remote Desktop Protocol Connections -->
      *[System[(Level=4 or Level=0) and (EventID=4624 or EventID=4634)]]
      and
      *[EventData[Data[@Name='LogonType']='10')]]
      and
    (*[EventData[Data[5]='10')]]
      or
      *[EventData[Data[@Name='AuthenticationPackageName'] = 'Negotiate']])
    </Select>
  </Query>
</QueryList>
```
| Event ID | Log | Level | LogonType | Authentication Pkg Name |
| --- | --- | --- | --- | --- |
| 4624 | Security | Information | 10 | Negotiate |
| 4634 | Security | Information | 10 | N/A |

### Software and Service Installation
As part of normal network operations, new software and services will be installed, and there is value in monitoring this activity. Administrators can review these logs for newly installed software or system services and verify that they do not pose a risk to the network.

It should be noted that an additional Program Inventory event ID 800 is generated daily on Windows 7 at 12:30 AM to provide a summary of application activities (e.g., number of new application installations). Event ID 800 is generated on Windows 8 as well under different circumstances. This event is beneficial to administrators seeking to identify the number of applications that were installed or removed on a machine.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| New Application Installation | 903, 904 | Informational | Microsoft-Windows-Application-Experience/Program-Inventory | Microsoft-Windows-Application-Experience |
| New Kernel Filter Driver | 6 | Informational | System | Microsoft-Windows-FilterManager |
| New MSI File Installed | 1022, 1033 | Informational | Application | MsiInstaller |
| New Windows Service | 7045 | Informational | System | Microsoft-Windows-FilterManager |
| Removed Application | 907, 908 | Informational | Microsoft-Windows-Application-Experience/Program-Inventory | Microsoft-Windows-Application-Experience |
| Summary of Software Activities | 800 | Informational | Microsoft-Windows-Application-Experience/Program-Inventory | Microsoft-Windows-Application-Experience |
| Update Packages Installed | 2 | Informational | Setup | Microsoft-Windows-Servicing |
| Updated Application | 905, 906 | Informational | Microsoft-Windows-Application-Experience/Program-Inventory | Microsoft-Windows-Application-Experience |
| Windows Update Installed | 19 | Informational | System | Microsoft-Windows-WindowsUpdateClient |

### System or Service Failures
System and Services failures are interesting events that may need to be investigated. Service operations normally do not fail. If a service fails, then it may be of concern and should be reviewed by an administrator. If a Windows service continues to fail repeatedly on the same machines, then this may indicate that an attacker is targeting a service.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Windows Service Fails or Crashes | 7022, 7023, 7024, 7026, 7031, 7032, 7034 | Error | System | Service Control Manager |

### Windows Defender Activities
Spyware and malware remain a serious problem and Microsoft developed an antispyware and antivirus, Windows Defender, to combat this threat. Any notifications of detecting, removing, or preventing these malicious programs should be investigated. In the event Windows Defender fails to operate normally, administrators should correct the issue immediately to prevent the possibility of infection or further infection. If a third-party antivirus and antispyware product is currently in use, the collection of these events is not necessary.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Action on Malware Failed | 1008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Detected Malware | 1006 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Failed to remove item from quarantine | 1010 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Failed to update engine | 2003 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Failed to update signatures | 2001 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Real-Time Protection failed | 3002 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Reverting to last known good set of signatures | 2004 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Scan Failed | 1005 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |
| Unexpected Error | 5008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender |

### Windows Firewall
If client workstations are taking advantage of the built-in host-based Windows Firewall, then there is value in collecting events to track the firewall status. For example, if the firewall state changes from on to off, then that log should be collected. Normal users should not be modifying the firewall rules of their local machine. The below events for the listed versions of the Windows operating system are only applicable to modifications of the local firewall settings.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Firewall Failed to load Group Policy | 2009 | Error | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Microsoft-Windows-Windows Firewall With Advanced Security |
| Firewall Rule Add | 2004 | Informational | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Microsoft-Windows-Windows Firewall With Advanced Security |
| Firewall Rule Change | 2005 | Informational | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Microsoft-Windows-Windows Firewall With Advanced Security |
| Firewall Rules Deleted | 2006, 2033 | Informational | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Microsoft-Windows-Windows Firewall With Advanced Security |

### Windows Update Errors
A machine must be kept up to date to mitigate known vulnerabilities. Although unlikely, these patches may sometimes fail to apply. Failure to update issues should be addressed to avoid prolonging the existence of an application issue or a vulnerability in the operating system or an application.

|   | ID | Level | Event Log | Event Source |
| --- | --- | --- | --- | --- |
| Hotpatching Failed | 1009 | Informational | Setup | Microsoft-Windows-Servicing |
| Windows Update Failed | 20, 24, 25, 31, 34, 35 | Error | Microsoft-Windows-WindowsUpdateClient/Operational | Microsoft-Windows-WindowsUpdateClient |
