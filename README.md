# Event Forwarding Guidance

This project hosts [scripts](./scripts/) and configuration files for aiding administrators in collecting security relevant Windows event logs using Windows Event Forwarding (WEF), and contains a recommended minimum set of events to collect. See [Spotting the Adversary with Windows Event Log Monitoring](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm) for more details on setting up WEF.

## Recommended Events
The [Events](./Events/) folder contains a minimum recommended set of Windows events to collect. Regardless of using WEF or a third party SIEM the list of recommended events should be useful as a starting point for what to collect. Collecting every single Windows event is not recommended. A better approach is to collect only events that provide value and insight into a system's state.

## Guidance
NSA Information Assurance has a security guide called [Spotting the Adversary with Windows Event Log Monitoring](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm).

## Links
* [Microsoft Windows Event Forwarding Resources](https://aka.ms/wef)
* [Use Windows Event Forwarding to help with intrusion detection](https://technet.microsoft.com/itpro/windows/keep-secure/use-windows-event-forwarding-to-assist-in-instrusion-detection)
* [Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
* [List of important events from Microsoft](https://technet.microsoft.com/windows-server-docs/identity/ad-ds/plan/appendix-l--events-to-monitor)
* [Microsoft Sysmon Tool](https://technet.microsoft.com/en-us/sysinternals/sysmon)

# License
See [LICENSE](./LICENSE.md).

## Disclaimer
See [DISCLAIMER](./DISCLAIMER.md).