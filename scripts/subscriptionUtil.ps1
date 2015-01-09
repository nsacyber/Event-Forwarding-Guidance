<#
.SYNOPSIS
Subscription Utility will is wrapper for managing subscriptions.

.DESCRIPTION
Subscription Utility provides the ability to easily automatic several functionality of wevtutil for handling subscriptions. This utility is simply a wrapper of wevtutil. 

.PARAMETER install
Install all the subscriptions specified by -dir. If combined with cdir, the directory specified, if it exist, will be deleted first then the new files are created.

.PARAMETER retry
Reactives subscriptions specified by -dir.

.PARAMETER remove
Removes subscriptions specified by -dir.

.PARAMETER dir
The directory that contains subscriptions to be used.

.PARAMETER cdir
The directory that will be used for custom views creation or removal. If a directory does not exist, it will be created. 

.PARAMETER cr
Removes custom views from %ProgramData%\Microsoft\Event Viewer\Views\. Must be supplied with cdir. The directory specified by cdir will be removed.

.PARAMETER ci
Install custom views from %ProgramData%\Microsoft\Event Viewer\Views\. Must be supplied with cdir. The directory specified by cdir will be created.

.INPUTS
System.String

.OUTPUTS
System.String

.EXAMPLE
.\subscriptionUtil.ps1 -install -dir ..\NT6 -cdir ..\CustomViews\NT6

This command will install subscriptions stored at the NT6 directory and custom views in the CustomViews\NT6 directory. Any old custom views are deleted forcibly. This assumes the subscriptions and custom view directory is stored at C:\.

.EXAMPLE
.\subscriptionUtil.ps1 -cdir ..\NT6 -cr

This will delete custom views for NT6 subscriptions currently in use.

.EXAMPLE
.\subscriptionUtil.ps1 -remove -dir ..\NT6 

Remove susbcriptions that were created from the NT6\  directory without removing custom views.

.LINK
http://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf
#>

[CmdletBinding(DefaultParameterSetName="help")]

param (
	[Parameter(Mandatory=$TRUE,parametersetname="install")]
	[ValidateNotNullOrEmpty()]
	[switch] $install,
	
	[Parameter(Mandatory=$TRUE,parametersetname="retry")]
	[ValidateNotNullOrEmpty()]
	[switch] $retry,
	
	[Parameter(Mandatory=$TRUE,parametersetname="remove")]
	[ValidateNotNullOrEmpty()]
	[switch] $remove,
	
	[Parameter(Mandatory=$TRUE,parametersetname="install")]
	[Parameter(Mandatory=$TRUE,parametersetname="retry")]
	[Parameter(Mandatory=$TRUE,parametersetname="remove")]
	[ValidateNotNullOrEmpty()]
	[string] $dir,
	
	[Parameter(Mandatory=$FALSE,parametersetname="remove")]
	[Parameter(Mandatory=$FALSE,parametersetname="install")]
	[Parameter(Mandatory=$TRUE,parametersetname="cremove")]
	[Parameter(Mandatory=$TRUE,parametersetname="cinstall")]
	[ValidateNotNullOrEmpty()]
	[string] $cdir,
	
	[Parameter(Mandatory=$FALSE,parametersetname="cinstall")]
	[ValidateNotNullOrEmpty()]
	[switch] $ci,
	
	[Parameter(Mandatory=$FALSE,parametersetname="cremove")]
	[ValidateNotNullOrEmpty()]
	[switch] $cr
)

New-Variable -Name INSTALLCV -value 1 -option constant -scope script
New-Variable -Name REMOVECV -value 2 -option constant  -scope script

<#
#	Now work (install/remove) on custom views
#>
function cvWorker([string] $d, [int32] $option){
	
	Write-verbose "Starting to work on custom views"

	if($option -eq $INSTALLCV){
		write-verbose ("Installing custom views at "+$d.gettype())

		#Does directory already exist in Event Viewer directory? If so delete it and it's contents.

		if($d.EndsWith("\")){
			if(Test-path ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-2])){
				del -Recurse ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-2])
			}
			new-item ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-2]) -type directory
			xcopy $d\* ("$env:ProgramData\Microsoft\Event Viewer\Views\"+ $d.Split("\")[-2]) /E /Q /Y
		}else{
			if(Test-path ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-1])){
				del -Recurse ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-1])
			}
			new-item ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-1]) -type directory
			xcopy $d\* ("$env:ProgramData\Microsoft\Event Viewer\Views\"+ $d.Split("\")[-1]) /E /Q /Y
		}			

	}elseif($option -eq $REMOVECV){

		write-verbose ("Deleting custom views at $env:ProgramData\Microsoft\Event Viewer\Views\" + $d)

		if($d.EndsWith("\")){
			del -Recurse ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-2])
		}else{
			del -Recurse ("$env:ProgramData\Microsoft\Event Viewer\Views\" + $d.Split("\")[-1])
		}
	}else{
		write-error "Not a valid option to work on Custom Views"
	}
	
	write-verbose "Work on CustomView Completed"
}

function install([string] $d){
  
	if($cdir){
		cvWorker $cdir $INSTALLCV
	}

	write-host "Starting registration of subscription"

	#get all .xml files
	$xmlGrp = Get-ChildItem  -recurse -include "*.xml" $d
	
	if($xmlGrp.count -eq 0){
		write-error "No items in $dir.. aborting this operation"
		return
	}
	
	foreach($file in $xmlGrp){
		write-host "Working on " $file.fullname
		wecutil cs $file.fullname
	}
	
	#Call retry
	retry $d
}

function retry([string] $d){
	write-host "Retrying subscription"
	
	$xmlGrp = Get-ChildItem -name -recurse -include "*.xml" $d
	
	if($xmlGrp.count -eq 0){
		write-error "No items in $dir.. aborting this operation"
		return
	}
	
	foreach($file in $xmlGrp){
		$fNExt = [io.path]::GetFileNameWithoutExtension($file)
		write-host "Working on " $fNExt
		wecutil rs $fNExt
	}

}

function remove([string] $d){

	if($cdir){
		cvWorker $cdir $REMOVECV
	}

	write-host "Deregistering of subscription"
	
	$xmlGrp = Get-ChildItem -name -recurse -include "*.xml" $d
	
	if($xmlGrp.count -eq 0){
		write-error "No items in $dir.. aborting this operation"
		return
	}
	
	foreach($file in $xmlGrp){
		$fNExt = [io.path]::GetFileNameWithoutExtension($file)
		write-host "Working on " $fNExt
		wecutil ds $fNExt
	}

}

# http://blog.technet.com/b/heyscripttingguy/archive/2011/05/11/check-for-admin-credentials-in-powershell-script.aspx
function Is-Admin(){
	if(-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")){
		return $false
	}
	
	return $true
}

if(-Not (Is-Admin)){
	write-warning "This script requires administrator privileges"
	exit
}


switch($PsCmdlet.ParameterSetName){
	"install" {install $dir}
	"retry" {retry $dir}
	"remove" {remove $dir}
	"cremove" {cvWorker $cdir $REMOVECV}
	"cinstall" {cvWorker $cdir $INSTALLCV}
}


