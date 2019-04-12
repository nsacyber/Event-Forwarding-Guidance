# Event Forwarding Guidance

This repository hosts content for aiding administrators in collecting security relevant Windows event logs using Windows Event Forwarding (WEF). This repository is a companion to [Spotting the Adversary with Windows Event Log Monitoring](https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf) paper. The list of events in this repository are more up to date than those in the paper.

The repository contains:

* [Recommended Windows events](./Events/) to collect. Regardless of using WEF or a third party SIEM, the list of recommended events should be useful as a starting point for what to collect. The list of events in this repository are more up to date than those in the paper.
* [Scripts](./scripts/) to create custom Event Log views and create WEF subscriptions.
* [WEF subscriptions](./Subscriptions/) in XML format.

## Links

* [Microsoft Windows Event Forwarding resources](https://aka.ms/wef)
* [Use Windows Event Forwarding to help with intrusion detection](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
* [Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630)
* [Microsoft's Threat Protection: Advanced security audit policy settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
* [Microsoft's Threat Protection: Security auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
* [List of important events from Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
* [Microsoft SysInternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [ACSC GitHub Windows Event Logging repository](https://github.com/AustralianCyberSecurityCentre/windows_event_logging)
* [ACSC Windows Event Logging Technical Guidance](https://acsc.gov.au/publications/protect/Windows_Event_Logging_Technical_Guidance.pdf)
* [Creating Custom Windows Event Forwarding Logs](https://blogs.technet.microsoft.com/russellt/2016/05/18/creating-custom-windows-event-forwarding-logs/)
* [Introducing Project Sauron](https://blogs.technet.microsoft.com/russellt/2017/05/09/project-sauron-introduction/)
* [Project Sauron GitHub repository](https://github.com/russelltomkins/project-sauron)
* [Windows Event Forwarding for Network Defense](https://medium.com/palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
* [Palantir Windows Event Forwarding GitHub repository](https://github.com/palantir/windows-event-forwarding)

## License

See [LICENSE](./LICENSE.md).

## Disclaimer

See [DISCLAIMER](./DISCLAIMER.md).
