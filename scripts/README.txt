The scripts in this directory need to run in a particular if starting
for the first time. These steps will setup Windows Event Collection subscriptions. 
The targeted groups are "Domain Computers"  and "Domain Controllers". These groups
can be changed later.

1 - Create Custom Views

	.\creatCV.ps1 -dir ..\Subscriptions\NT6 -odir ..\CustomViews\Monitor
	
2 - Add "Domain Computers" and "Domain Controllers" SIDs to subscriptions

	.\Fill-GroupName.ps1 -sid "Domain Computers" -dir ..\Subscriptions\NT6
	Follow by
	.\Fill-GroupName.ps1 -sid "Domain Controllers" -dir ..\Subscriptions\NT6 -append

3 - Add Domain name for Pass the Hash Filter

    This is a manual edit.
    - Navigate to ..\Subscriptions\NT6\ and open AccountLogons.xml with an editor
    - Replace the word 'TEST' on Line 46 and 60 with your Domain's Name

    Example:
	  ..snip..
		*[EventData[Data[@Name='TargetDomainName']!='TEST']]
	  ..snip..
	  with
	  ..snip..
		*[EventData[Data[@Name='TargetDomainName']!='MYDOMAINNAME']]
	  ..snip..

4 - Install subscriptions (this step assumes you have configured WinRM and Windows Event Collection services, if not read section 2.3 of security guidance)

	.\subscriptionUtil.ps1 -install -dir ..\Subscriptions\NT6 -cdir ..\CustomViews\Monitor

5 - Open up Event Viewer (eventvwr.msc)
	See Subscription and Custom Views for Verification

6 - Ready!