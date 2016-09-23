<#
.SYNOPSIS
Creates Custom Views based on subscriptions.

.DESCRIPTION
Custom Views are only created manually via the Event Viewer. This script is an attempt to automate the process by using existing subscriptions.

This script relies on each subscription to follow a specific format. Each subscription MUST have a XML comment ( <!-- COMMENT --> ) prior to any Select node (XPath query). The XML comment will be used as the name of the Custom View being created. For example, "<!-- Account Lockouts -->" will create a Custom View named "Account Lockouts". Whitespace appended or prepended to the name are ignored. The script will still parse a subscription regardless if there are multiple Select or Query nodes within one subscription as long it follows the format. When a subscription has multiple Select, a Custom View is created for each one.

Custom Views focusing on events occurring during a period of time can be created as well under its own directory.

.PARAMETER dir
Specifies the directory the subscriptions to parse to create Custom Views. 

.PARAMETER odir
Specifies the output directory where custom views are created. If the -time parameter is enabled, odir is to specify the output directory where other sub-directories are created. 

.PARAMETER time
Indicates time filtered custom views will be created. All units of time are converted internally into milliseconds. Only one additional time option can be specified per operation. The odir MUST specified the directory to stored newly created custom views. A timediff condition will be appended to the XPath query identified in each subscription. 

.PARAMETER mins
The number of minutes to filter. Can not be combined with other time options. Must be supplied with -time.

.PARAMETER hours
The number of hours to filter. Can not be combined with other time options. Must be supplied with -time.

.PARAMETER days
The number of days to filter. Can not be combined with other time options. Must be supplied with -time.
	
.PARAMETER weeks
The number of weeks to filter. Can not be combined with other time options. Must be supplied with -time.

.PARAMETER months
The number of months to filter. Can not be combined with other time options. Must be supplied with -time.
	
.INPUTS
System.String

.OUTPUTS
System.String

Results are stored in XML files.

.EXAMPLE
.\creatCV.ps1 -dir ..\subscriptions\nt6 -odir ..\customviews\nt6

--- Output ---
Starting work on (AccountLocked.xml)
Creating View_0.xml...
COMPLETED

Starting work on (AccountLogons.xml)
Creating View_1.xml...
Creating View_2.xml...
Creating View_3.xml...
Creating View_4.xml...
COMPLETED
..snip..

.EXAMPLE
.\creatCV.ps1 -dir ..\Subscriptions\Combined\ -odir ..\CustomViews\Combined
Starting work on (XV_AppCrash.xml)
extract_cvn : Previous Sibling does not exist
..snip..
extract_cvn : This is not a XML comment, leaving..
..snip..
extract_cvn : This is not a XML comment, leaving..
..snip..
COMPLETED


Note: These errors are in result of the subscription not conforming to the parsing format: not supplying a XML comment prior to Select node.

.EXAMPLE
.\creatCV.ps1 -dir ..\Subscriptions\NT6\ -odir ..\CustomViews\TimeFilter -time -mins 180

-- Output --
Starting work on (AccountLocked.xml)
Creating Last 180 Minutes\ directory under ..\CustomViews\TimeFilter\
COMPLETED
..snip..

.LINK
https://www.iad.gov/iad/library/ia-guidance/security-configuration/applications/spotting-the-adversary-with-windows-event-log-monitoring.cfm
#>

[CmdletBinding(DefaultParametersetName="default")]

param (
    [Parameter(Mandatory=$TRUE,parametersetname="time")]
    [Parameter(Mandatory=$TRUE,parametersetname="default")]
    [ValidateNotNullOrEmpty()]
    [string] $dir,

	[Parameter(Mandatory=$TRUE, parametersetname="time")]
	[switch] $time,
	
	[Parameter(Mandatory=$FALSE, parametersetname="time")]
	[ValidateNotNullOrEmpty()]
	[System.ValueType] $mins,
	
	[Parameter(Mandatory=$FALSE, parametersetname="time")]
	[ValidateNotNullOrEmpty()]
	[System.ValueType] $hours,
	
	[Parameter(Mandatory=$FALSE, parametersetname="time")]
	[ValidateNotNullOrEmpty()]
	[System.ValueType] $days,
	
	[Parameter(Mandatory=$FALSE, parametersetname="time")]
	[ValidateNotNullOrEmpty()]
	[System.ValueType] $weeks,
	
	[Parameter(Mandatory=$FALSE, parametersetname="time")]
	[ValidateNotNullOrEmpty()]
	[System.ValueType] $months,
    
    [Parameter(Mandatory=$TRUE,parametersetname="time")]
    [Parameter(Mandatory=$TRUE,parametersetname="default")]
    [ValidateNotNullOrEmpty()]
	[string] $odir
)


#
# Const Variables
#

Set-Variable ext -option Constant -value ".xml" -Scope "script"
# Custom View basic layout
Set-Variable start -option constant -value "<ViewerConfig>`n`t<QueryConfig>`n`t`t<QueryParams>`n`t`t`t<UserQuery/>`n`t`t</QueryParams>`n`t`t<QueryNode>" -Scope "script"
Set-Variable end -option constant -value "`n`t`t</QueryNode>`n`t</QueryConfig>`n</ViewerConfig>" -Scope "script"
Set-Variable name_s -option constant -value "`n`t`t`t<Name>" -Scope "script"
Set-Variable name_e -option constant -value "</Name>" -Scope "script"
Set-Variable query_s -option constant -value "`n`t`t`t<QueryList>`n`t`t`t`t<Query Id=`"0`">`n" -Scope "script"
Set-Variable query_e -option constant -value "`n`t`t`t`t</Query>`n`t`t`t</QueryList>" -Scope "script"



# This is to keep count how the number of views created 
# Also for naming of CVs, so there is no overlap.
$view_c = 0


#
# Functions
#

# Returns a <Select></Select> query string
function extractQuery([System.Xml.XmlElement] $select){
	try{
		<# This will take a bit of work...
		# This function may return either a single or an array of queries
		#
		# For each file, extract all the queries (each select element)
		# Ignore, the suppress element as there was for the source
		
		# Remember the XPath query is part of CDATA so it needs to be extracted
		# as a string. Afterwards, convert the QueryList into XML. 
		#>
	
		$xpath = $select.innertext
						
		write-debug $xpath
				
		#Change the Path to ForwardedEvents for CustomView
		$query = "<Select Path=`"ForwardedEvents`">"+$xpath+"</Select>`n"
		
		# Return query
		$query
	}catch [Exception]{
		write-error "Issue with obtaining XPath query..."
		write-error ($_.Exception.Message)
		return -1
	}
}

<#
# Get Custom View's new name from comments. 
# NOTE: These comments MUST be appear prior the each Select node. Otherwise, it will not work.
# NOTE: Even if there are multiple selects or queryes bunched up together, a comment must be
# NOTE: prior to a Select node
#
# Example:
#  <Query Id="0" Path="Application">
#      <!-- Application Error -->  <-- Must be there, leading & trailing whitespace are removed
#    <Select Path="Application">*[System[Provider[@Name='Application Error'] and (Level=2)]]</Select>
#  </Query>
#
#>
function extract_cvn([System.Xml.XmlElement] $select){
	try{
		if($select.PreviousSibling -eq $null){
			write-error "Previous Sibling does not exist"
			return -1
		}elseif($select.PreviousSibling.gettype().Name -ne "XmlComment"){
			write-error "This is not a XML comment, leaving.."
			return -1
		}
	
		$comment = $select.PreviousSibling.Innertext.trim()
		write-debug "Custom View's new name, ($comment)"
		
		$comment
	}catch [Exception]{
		write-error "Issue with obtaining Comment..."
		write-error ($_.Exception.Message)
		return -1
	}
}

<#
# Creates the actual file
# cv_creat(the new CV content, the file it was based on, )
#>
function cv_creat([System.string] $cv,[System.string] $n_file,[System.string] $time_dir){
	
	try{
		$view_f = "View_$view_c$ext"
		$full = ""
	
		# Now create a CV for this filter....
		write-debug "Custom View's new name, ($view_f)"
	
		#Time CustomView Directories, If directory does not exist create it
		if($script:time.IsPresent){
			if(!(Test-path -path "$script:odir$time_dir" -PathType "Container")){
					write-host "Creating $time_dir directory under $script:odir"
					new-item "$script:odir$time_dir" -type directory | out-null
			}else{
				write-host "Creating $view_f in $script:odir$time_dir directory"
			}
		}else{
			write-host "Creating $view_f in $script:odir directory"
		}
		
		if($script:time.IsPresent){
			$full = $script:odir + $time_dir + $view_f
		}else{
			$full = $script:odir  + $view_f
		}

        write-debug "Creating CV in $full"

        out-file -filepath $full -inputobject $cv -encoding ASCII -Force 
		
		$script:view_c++
		
		write-debug "Completed creating new custom view."
	}catch [Exception]{
		write-host "Issue with creating new CV..."
		write-host ($_.Exception.Message)
		return -1
	}
}

<#
# This function is creator of a custom view per filter
#>
function cs_setup([System.string] $filename,[System.string]  $dir){
	try{

        write-debug $dir$filename
	
		$f_con = Get-Content ("$dir$filename") -ErrorAction:SilentlyContinue -ErrorVariable er
		
		if($er){
			write-error $er
			return -1
		}
		
		$er.clear()
		
		#Convert subscription into parse-able XML
		$sub_xml = [xml]$f_con 
	}catch [Exception]{
		write-error "Issue with opening or converting..."
		write-error ($_.Exception.Message)
		return -1
	}
	
	# Call extract query function to get queries
	# Now you have a number of queries used in subscription
	# Need to find out their purpose, call extract_cvname function to get name from comment

	$querylist = [xml]$sub_xml.Subscription.Query.InnerText

	write-debug $sub_xml.Subscription.Query.InnerText
	 		
	$children = $querylist.Querylist.ChildNodes

	# Subscription *may* have multiple Query nodes with multiple Select nodes. 
	# This will iterate through each Query node 
	foreach($child in $children){
		
		$qc_children = $child.childnodes.count
		write-debug "Query children count ($qc_children)"

		# Does this Query node have children? 
		if($qc_children -gt 0){
			
			foreach($select in $child.select){
				
				# Get comment that have Custom View's Name/purpose
				$cv_name = extract_cvn $select
				
				if($cv_name -eq -1){
					# Even though there is an error with this Select node,
					# the next node may be fine
					write-debug "Issue, Going to next Select Node"
					continue	
				}
				
				# Get this Select node's XPath query
				$select_q = extractQuery $select
				
				if($select_q -eq -1){
					# Even though there is an error with this Select node,
					# the next node may be fine
					write-debug "Issue, Going to next Select Node"
					continue	
				}
				
				# New Custom View
				$cv_new = $start + $name_s + $cv_name + $name_e
				
				
				#
				# Before finishing the construction of the Custom View. Is time node requested?
				#
				if($script:time.IsPresent){
				
					#update the select query with the new time comparison
					$time_items = add-timecond $select_q
					$cv_new += $query_s + $time_items[0] + $query_e + $end
					
					write-debug "New Custom View...`n$cv_new`nEnd of New Custom View"
				
					$cv_r = cv_creat $cv_new $filename $time_items[1]
				}else{
					# Adds each Select element
					$cv_new += $query_s + $select_q + $query_e + $end
					
					write-debug "New Custom View...`n$cv_new`nEnd of New Custom View"
				
					$cv_r = cv_creat $cv_new $filename
				}
				
				if($cv_r -eq -1){
					# Even though there is an error with this Select node,
					# the next node may be fine
					write-debug "Issue creating, Going to next Select Node"
					continue	
				}
				
			}
			write-debug "No more Query children, going to next subscription file.."
			
		}# No children, next Query node
	}
	
	# Now, time to create a CV for each. This function will create the custom view file
	# call creat_cv function for each filter (passing individual filter and their name)
}


function startCV([System.Array] $s_files, [System.string] $dir){

	# Now for the fun part, information extraction!
	foreach ($file in $s_files){
	
		write-host "Starting work on ($file)"
		
		# This function creates the new custom view
		$status = cs_setup $file $dir
	
		if($status -eq -1){
			write-host "Skipping subscription.. an error occur while processing"
			continue	
		}

		write-host "COMPLETED`n`n"
	}

}


<#
# Time. Modify the query to append a timediff condition
#
# Example: 
#  
# *[System[(Level=2) and (EventID=1000) and TimeCreated[timediff(@SystemTime) &lt;= 3600000]]]
# That is milliseconds on the RHS of the less than operator
# Dealing with query modification not need. Only need to append an "and *[System[TimeCreated[timediff(@SystemTime) &lt;= $time]]]" 
# instead
#>
function add-timecond([string] $query){
	write-debug "Modifying the following query: $query"

    $tmpxml = [xml]$query
    $rquery = $tmpxml.select."#text"

    write-debug "Only XPath query $rquery"
    

	$select_b = "<Select Path=`"ForwardedEvents`">"
	$select_e = "</Select>"
	$new_q = ""
	$time_name = ""
	
	# User can only specify one time option at a time
	# Let PowerShell handle the integer conversions besides manual casting.
	if($script:mins){
		$minsN = [System.Math]::round($mins)
		$time_name = Get-TimeName $minsN "Minutes"
		$minsN *= 60000
		
		$new_q = $rquery + " and *[System[TimeCreated[timediff(@SystemTime) &lt;= $minsN]]]"
	}elseif($script:hours){
		$hrsN = [System.Math]::round($script:hours)
		$time_name = Get-TimeName $hrsN "Days"
		$hrsN *= 3600000
	 
		$new_q = $rquery + " and *[System[TimeCreated[timediff(@SystemTime) &lt;= $hrsN]]]"
	}elseif($script:days){
		$daysN = [System.Math]::round($script:days)
		$time_name = Get-TimeName $daysN "Days"
		$daysN *= 86400000
	 
		$new_q = $rquery + " and *[System[TimeCreated[timediff(@SystemTime) &lt;= $daysN]]]"
	}elseif($script:weeks){
		$weeksN = [System.Math]::round($script:weeks)
		$time_name = Get-TimeName $weeksN "Weeks"
		$weeksN *= 604800000
	
		$new_q = $rquery + " and *[System[TimeCreated[timediff(@SystemTime) &lt;= $weeksN]]]"
	}elseif($script:months){
		$monthN = [System.Math]::round($script:months)
		$time_name = Get-TimeName $monthN  "Months"
		$monthN *= 2629740000 
	
		$new_q = $rquery + " and *[System[TimeCreated[timediff(@SystemTime) &lt;= $monthN]]]"
	}
	
	$new_q = $select_b + $new_q + $select_e
	
	write-debug "New query: $new_q"
	
	#return an array...
	$new_q,$time_name
}

<#
# Make a useful time directory name
#>
function Get-TimeName([System.ValueType] $duration, [string] $unit){
	$time_name = "Last $duration $unit\"
	
	return $time_name
}

<#
Verify that any necessary parameters are set
#>
function timepreparer(){
	
	# If any of the parameters are set, continue
	if($script:mins -or $script:hours -or $script:days -or $script:weeks -or $script:months){
		main
	}else{
		Write-Error "Need either -mins, -days, -weeks, or -months parameter when -time is specified"
	}
}

<#
# Main
#>

function main(){

    try{

		if(-Not (Test-Path -path $script:dir -PathType "Container")){
			throw "Directory $script:dir does not exist"
		}
	
        #If directory does not exist create it
		if(!(Test-path -path ($script:odir) -PathType "Container")){
                write-debug "Creating $script:odir directory"
				new-item $script:odir -type directory | out-null
		}
		
		#Needs this '\' since this string will be used later on
		if($script:dir[-1] -ne "\"){
            $script:dir += "\"
        }
		
		if($script:odir[-1] -ne "\"){
            $script:odir += "\"
        }
		
        $fnames = get-childitem -path $script:dir -name

        if($fnames.count -eq 0){
            write-host "Nothing to work on... bailing out.`n"
        }else{

            startCV $fnames $script:dir
        }
   	}catch [Exception]{
		write-error ($_.Exception.message)
		return -1
	}
    
}

switch($PsCmdlet.ParameterSetName){
    "time" {timepreparer}
	"default" {main} 
}
