<#
.SYNOPSIS
Sets the AllowedSourceDomainComputers tags of specified subscriptions.

.DESCRIPTION
Fill-GroupName will fill in the empty <AllowedSourceDomainComputers> tags in each subscription with the supplied SID.

.PARAMETER sid
Supply the SID or object's (computer/group) name that will be entered into the AllowedSourceDomainComputer node of each NT5 susbcriptions. This will overwrite any existing SDDL unless the append parameter is specified.

If a name is given (e.g., "UserA" or "Domain Computers"), its respective SID value will be identified and used. 

.PARAMETER append
The supplied SID or object name is appended to each subscription listed by file.

.PARAMETER dir
The directory of subscriptions.

.PARAMETER file
Supply a file that contains a list of absolute paths to subscription filenames (one per line). Must be used in conjunction with the sid parameter. Can be used with append.

.INPUTS
System.String

.OUTPUTS
System.String

Results are reflected in subscription XML files.

.EXAMPLE
.\Fill-GroupName.ps1  -sid "Domain computers" -file .\LIST  -append

-- Output --
[-] Invalid SID. Maybe it is an object's name, Verifying....
[+] Verified that Domain computers is an object's name and got SID (S-1-5-21-000000000-0000000000-0000000000-515)

A list of subscriptions will have the SID value of Domain Computer appended to existing SDDL.

.EXAMPLE
.\Fill-GroupName.ps1  -sid "Domain computers"  -dir ..\Subscriptions\NT6
Verified that S-1-5-21-000000000-0000000000-0000000000-515 is an object's name and got SID

Starting with C:\EvtFwdSubscriptions\Subscriptions\NT6\AccountLocked.xml, using SID (S-
1-5-21-000000000-0000000000-0000000000-515)
..snip..
Starting with C:\EvtFwdSubscriptions\Subscriptions\NT6\WinUpdateErr.xml, using SID (S-1
-5-21-000000000-0000000000-0000000000-515)
[+] Completed setting the targeted SID value to subscriptions in ..\Subscriptions\NT6

Set the Domain Computers SID to all subscriptions in NT6\

.EXAMPLE
.\Fill-GroupName.ps1  -sid "Domain controllers"  -dir ..\Subscriptions\NT6 -append
Verified the object's name and got SID (S-1-5-21-000000000-0000000000-0000000000-516)

Starting with C:\EvtFwdSubscriptions\Subscriptions\NT6\BsodErr.xml, using SID (S-
1-5-21-000000000-0000000000-0000000000-516)
[+] Completed setting the targeted SID value to subscriptions in ..\Subscriptions\NT6

.EXAMPLE
.\Fill-GroupName.ps1  -sid "myname"  -dir ..\Subscriptions\NT6 -append
Set-SubscripSID : Invalid object name/SID
At C:\EvtFwdSubscriptions\scripts\Fill-GroupName.ps1:285 char:3
+         Set-SubscripSID $script:sid $sfiles
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Set-SubscripSID

Invalid object name/SID used.

.LINK
https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm
#>


[CmdletBinding(DefaultParameterSetName="help")]

param (
	[Parameter(Mandatory=$TRUE,parametersetname="list")]
	[Parameter(Mandatory=$TRUE,parametersetname="main")]
	[ValidateNotNullOrEmpty()]
	[string] $sid,
	
	[Parameter(Mandatory=$TRUE,parametersetname="list")]
	[ValidateNotNullOrEmpty()]
	[string] $file,
	
	[Parameter(Mandatory=$TRUE,parametersetname="main")]
	[ValidateNotNullOrEmpty()]
	[string] $dir,
	
	[Parameter(Mandatory=$FALSE,parametersetname="list")]
	[Parameter(Mandatory=$FALSE,parametersetname="main")]
	[switch] $append
)

<#
#
# Appends a SID
#
#>
function append-sid([string] $sub, [string] $sid){
	try{
		$replace = '$1$2(A;;GA;;;'+$sid+')$3'
		$pattern = "(SourceDomainComputers>)(.*)(S:<\/Allow)"
		$r = $sub -replace $pattern, $replace
	}catch [Exception]{
		write-error "Issue with adding appending a new sid...`n"
		write-error ($_.Exception.Message)
		return -1
	}

	return $r
}

function fill($fileN, $s){
	
	try{
		# Now get the subscription file content
		$fcontents = Get-Content $fileN
	}catch [Exception]{
		write-error ($_.Exception.Message)
		return -1
	}
		
	write-debug "Got content from $f. Now setting the SID value ($rsid)"
		
	$result = $null
	
	#Is this an append request?
	if($append.IsPresent){
		if( ($result = append-sid $fcontents $s) -eq -1){
			return -1
		}
	}else{

		$replace = "SourceDomainComputers>O:NSG:BAD:P(A;;GA;;;$s)S:</Allow"
		$pattern = "(SourceDomainComputers>)(.*)(<\/Allow)"
			
		$result = $fcontents -replace $pattern, $replace 
	}
	
	# Write results to subscription
	
	try{
		write-debug "Going to write new results $result`nto $fileN"	
		Out-File -FilePath $fileN -Force -InputObject $result -Encoding "ASCII"
	}catch [Exception]{
		write-error "Issue with writing to file..."
		write-error ($_.Exception.Message)
		return -1
	}
	
	return 0
}


<#
#
# Find the SID value of an Active Directory object (computer/group/user). Using local objects
# for subscriptions, can be done if AllowedNonDomainComputers is set.
#
#>
function get-sid([string] $obj_name){
	# From: http://technet.microsoft.com/en-us/library/ff730940.aspx
	
	$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	
	try{
		$obj = New-Object System.Security.Principal.NTAccount($domain.name, $obj_name)
		$sid = $obj.Translate([System.Security.Principal.SecurityIdentifier])
		return $sid.value	
	}catch [Exception]{
		return -1
	}
}

<#
#
# Test if submitted sid was correct SID
#
#>
function test-sid([string] $strsid){
	# From: http://technet.microsoft.com/en-us/library/ff730940.aspx
	try{
		$obj = New-object system.security.principal.securityidentifier($strsid)
		$obj.Translate([System.Security.Principal.NTAccount])
		return $true
	}catch [Exception]{
		return $false
	}
}


<#
#
# Append additional SIDs to AllowDomainSourceComputers of each subscription list by -file
#
#>
function append-sidList(){
	try{
		$rsid = $null
		$result = $null
		
		if( -Not (test-sid $script:sid) ){
			write-host "[-] Invalid SID. Maybe it is an object's name, Verifying...."
		
			if( ($rsid = get-sid $script:sid) -eq -1){
				write-error "Invalid object name/SID`n"
				return
			}
			
			write-host "[+] Verified the object's name and got SID ($rsid)`n"
			
			write-debug "Got $rsid as the SID to use"
			# Now using the actual SID value
		}
	
		#Get contents from file specified by -file
		$list_sub = Get-content $script:file

		#Iterate through each subscription in file
		foreach($f in $list_sub){
		
			#Skip whitespace lines and lines beginning with '#'
			if( ($f -match '^\s$|^#') -or [string]::IsNullOrEmpty($f)){
				continue
			}
		
			write-debug "Got $f from $script:file"
			
			if( -not (Test-Path $f -pathtype "leaf" -include "*.xml")){
				write-host "$f does not exist... next..."
				continue
			}
			
			
			#Update SDDL
			if( ($result = fill $f $rsid) -eq -1){
				continue
			}			
		}
	
	
	}catch [Exception]{
		write-error "Issue with setting SID to list of subscriptions name...`n"
		write-host ($_.Exception.Message)
		return -1
	}
}

<#
#
# This function will set the supplied SID for all subscriptions with -dir
#
#>
function Set-SubscripSID([string]$s, [system.Array]$sfiles){

	<#
	# First, Verify the submitted SID is valid. If not, check it is 
	# an object's name to identify the SID value. If all these fail
	# bail out.
	#>
	if( -Not (test-sid $s) ){
		if( ($s = get-sid $s) -eq -1){
			write-error "Invalid object name/SID`n"
			return
		}
		
		write-host "Verified the object's name and got SID ($s)`n"
		# Now using the actual SID value
	}

 	foreach($sf in $sfiles){
		write-host "Starting with $sf, using SID ($s)"
		
		if( (fill $sf $s) -eq -1){
			return
		}
	}

	Write-Host "[+] Completed setting the targeted SID value to subscriptions in $script:dir"
}


<#
#
# Main
#
#>

function main(){
	if(!(Test-path -path ($script:dir) -PathType "Container")){
		write-debug "$script:dir directory does not exist"
	}else{
		$sfiles = @()
		
		write-debug "Getting Child Items from $script:dir"
		#Get absolute subscriptions names
		Get-ChildItem -Path $script:dir -recurse -Include "*.xml" | % {$sfiles += $_.FullName}
		
		write-debug ("There were "+ $sfiles.count +" file(s) in $script:dir")
		
		if($sfiles.count -eq 0){
			write-host "There were no matching files found in $script:dir"
			return
		}
	
		Set-SubscripSID $script:sid $sfiles
	}
}


switch($PsCmdlet.ParameterSetName){
	"main" {main}
	"list" {append-sidList}
	"help" {get-help ./Fill-GroupName.ps1}
}
