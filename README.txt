Spotting the Adversary with Windows Event Monitoring security guidance from NSA IAD provided several 
subscriptions to used for collecting specific events from Windows clients in a domain. This package complements 
the security guidance document. Tis package consist of several items:
* PowerShell scripts to automate certain task involving Windows Event Collection administration
	- Includes a script to create Custom Views for Event Viewer
* Subscriptions targeting Windows 7+ (specified events to collect)

Most of the subscriptions are documented within their respective XML file. 

Each subscription will have the AllowedSourceDomainComputers tag empty. AllowedSourceDomainComputers tags MUST be filled
with the intended group. 

All PowerShell script were developed and require PowerShell 4.0 (dot Net 4.5). 

Structure
-=-=-=-=-=-=-=--=-=-=-=-=-=-=--=-=-=-=-=-=-=-
Windows Vista+ subscriptions - Title.xml

Subscriptions, if using creatCV.ps1 to create custom views, MUST conform the the following layout:

Example:
#  <Query Id="0" Path="Application">
#      <!-- Application Error -->  <-- Must be here, leading & trailing whitespace are removed
#    <Select Path="Application">*[System[Provider[@Name='Application Error'] and (Level=2)]]</Select>
#  </Query>

Subscriptions
-=-=-=-=-=-=-=--=-=-=-=-=-=-=--=-=-=-=-=-=-=-
The Subscriptions directory consist of two directories:

	* NT6 - NT6 targeted subscriptions. Expanded version of subscriptions provided in "Spotting the Adversary with Windows Event Monitoring"
	* samples - These are subscriptions from NT6 that were that were shorten for 
		"Spotting the Adversary with Windows Event Monitoring" paper. There are no differences in what 
		events are collected

INSTALLATION STEPS
-=-=-=-=-=-=-=--=-=-=-=-=-=-=--=-=-=-=-=-=-=-

Not really "installation", the subscriptions need to be part of the Windows Event Collector. The 
general steps are: 
* Create Custom Views
* Filled in a targeted group/machines SDDL
* Install subscriptions

A second README.txt within the scripts directory continues this discussion

Happy Event Collecting!
