For initial setup, the scripts in this directory must run in a particular order. These steps will setup **Windows Event Collection** subscriptions. 
The targeted groups are "domain computers"  and "domain controllers". These groups can be changed later.

1. Create Custom Views
    ```
	.\creatCV.ps1 -dir ..\Subscriptions\NT6 -odir ..\CustomViews\Monitor
	```
	
1. Add "Domain Computers" and "Domain Controllers" security identifiers (SID) to subscriptions
    ```
    .\Fill-GroupName.ps1 -sid "Domain Computers" -dir ..\Subscriptions\NT6
	Follow by
    .\Fill-GroupName.ps1 -sid "Domain Controllers" -dir ..\Subscriptions\NT6 -append
    ```
1.  Add domain name for the Pass the Hash (PtH) filter. *(This is a manual edit.)*
    - Navigate to `..\Subscriptions\NT6\` and open AccountLogons.xml with an editor
    - Replace the word `TEST` on Line 46 and 60 with your domain name
    ```
     ..snip..
    *[EventData[Data[@Name='TargetDomainName']!='TEST']]
    ..snip..
    with
    ..snip..
    *[EventData[Data[@Name='TargetDomainName']!='MYDOMAINNAME']]
    ..snip..
    ```

1. Install subscriptions *(If you have not configured **WinRM** and **Windows Event Collection** services, read section 2.3 of security guidance.)*
    ```
    .\subscriptionUtil.ps1 -install -dir ..\Subscriptions\NT6 -cdir 
    ..\CustomViews\Monitor
    ```

1. Open **Event Viewer** (`eventvwr.msc`) and verify Subscription and Custom Views


> Written with [StackEdit](https://stackedit.io/).
