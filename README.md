# Event Collection Guidance

## About This Project
This project hosts [scripts](./Scripts/) and configuration files for aiding administrators in collecting security relevant Windows event logs using Windows Event Forwarding (WEF), and contains a recommended minimum set of events to collect. See [Spotting the Adversary with Windows Event Log Monitoring](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm) for more details on setting up WEF.

## Recommended Events
The [Events](./Events/) folder contains a minimum recommended set of Windows event logs to collect. Regardless of using WEF or a third party SIEM the list of recommended events should be useful as a starting point for what to collect. Collecting every single windows event is not recommended. A better approach is to collect only events that provide value and insight into a systems state.

## Guidance
NSA Information Assurance has a security guide called [Spotting the Adversary with Windows Event Log Monitoring](https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm)

## Links 
* [Use Windows Event Forwarding to help with intrusion detection](https://technet.microsoft.com/itpro/windows/keep-secure/use-windows-event-forwarding-to-assist-in-instrusion-detection)
* [Windows 10 and Windows Server 2016 security auditing and monitoring reference](<https://www.microsoft.com/en-us/download/details.aspx?id=52630>)

## License
This Work was prepared by a United States Government employee and, therefore, is excluded from copyright by Section 105 of the Copyright Act of 1976.

Copyright and Related Rights in the Work worldwide are waived through the [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) [Universal license](https://creativecommons.org/publicdomain/zero/1.0/legalcode).

Portions of specific scripts are licensed under [Microsoft Limited Public License](http://msdn.microsoft.com/en-us/cc300389.aspx).

## Disclaimer of Warranty
This Work is provided "as is." Any express or implied warranties, including but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the United States Government be liable for any direct, indirect, incidental, special, exemplary or consequential damages (including, but not limited to, procurement of substitute goods or services, loss of use, data or profits, or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this Guidance, even if advised of the possibility of such damage.

The User of this Work agrees to hold harmless and indemnify the United States Government, its agents and employees from every claim or liability (whether in tort or in contract), including attorneys' fees, court costs, and expenses, arising in direct consequence of Recipient's use of the item, including, but not limited to, claims or liabilities made for injury to or death of personnel of User or third parties, damage to or destruction of property of User or third parties, and infringement or other violations of intellectual property or technical data rights.

Nothing in this Work is intended to constitute an endorsement, explicit or implied, by the United States Government of any particular manufacturer's product or service.

## Disclaimer of Endorsement
Reference herein to any specific commercial product, process, or service by trade name, trademark, manufacturer, or otherwise, in this Work does not constitute an endorsement, recommendation, or favoring by the United States Government and shall not be used for advertising or product endorsement purposes.