#requires -version 2
<#
.SYNOPSIS
Gets default and fine grained password policies
 
.AUTHOR
Chris Mewett
 
.DESCRIPTION
Queries Active Directory for password policies and outputs data in a CSV file. Initially written for recording / processing by security analytics
 
.PARAMETER verbose
Provide status information as the script runs
 
.PARAMETER OutputLocation
Default: The directory the script is called from.
 
.INPUTS None
No input is accepted
 
.OUTPUTS CSV file
A Comma Separated Value (CSV) file named [foo]-[string of numbers].csv in the OutputLocation specified
 
.EXAMPLE
audit-adpasswordpolicies.ps1 -outputlocation d:\ 
Ouputs CSV to the root of d:\
 
.LINK  
https://chrismewett.net/
#>
 
[CmdletBinding()]
Param(
[Parameter(Mandatory=$false,Position=1,ParameterSetName="run")]
[validatescript({ test-path $_ })]
[string]$outputlocation = (get-location).path,
[Parameter(Mandatory=$false,Position=1,ParameterSetName="run")]
[string]$query = 'default',
[Parameter(Mandatory=$false,Position=1,ParameterSetName="run")]
[string]$grouplist,
Parameter(Mandatory=$false,Position=1,ParameterSetName="run")]
[string]$outputfile = ('passwordpolices-' + ( get-date -uformat +-%s ) + '.csv'),
[switch]$lint

)
 
$outputfile = $outputlocation + "\" + $outputfile
$Env:ADPS_LoadDefaultDrive = 0
Import-Module ActiveDirectory
 
 
function GenerateReport {
	$cwd = (get-location).Path
	New-PSDrive -name "AD" -root "" -PSProvider ActiveDirectory -server (get-addomain).PDCEmulator

	$output = New-Object System.Collections.ArrayList
	write-verbose "[+] retrieving default passsword policy"
	$defaultpolicy = Get-ADDefaultDomainPasswordPolicy

	[void]$output.Add((New-Object PSCustomObject -Property @{
		"dn" = $defaultpolicy.DistinguishedName
        	"type" = "default";
        	"name" = "default";
        	"AppliesTo" = "default"; 
           	"ComplexityEnabled" = $defaultpolicy.ComplexityEnabled
            	"LockoutDuration" = $defaultpolicy.LockoutDuration
           	"LockoutObservationWindow" = $defaultpolicy.LockoutObservationWindow;
            	"LockoutThreshold" = $defaultpolicy.LockoutThreshold;
            	"MaxPasswordAge" = $defaultpolicy.MaxPasswordAge;
            	"MinPasswordAge" = $defaultpolicy.MinPasswordAge;
            	"MinPasswordLength" = $defaultpolicy.MinPasswordLength;
            	"PasswordHistoryCount" = $defaultpolicy.PasswordHistoryCount;
            	"Precedence" = "-1";
            	"ReversibleEncryptionEnabled" = $defaultpolicy.ReversibleEncryptionEnabled;
            	"whenChanged" = "undefined";
            	"whenCreated" = "undefined";
            	"objectClass" = "undefined";
            	"saclcount" = "undefined";
            	"denycount" = "undefined";
            	"error" = "";
	}))

	set-location ad:
	write-verbose "[+] searching for fine grained password policies"
	$fgcontainer = Get-ChildItem (get-addomain).systemscontainer | where-object ObjectClass -eq "msDS-PasswordSettingsContainer"

	get-childitem $fgcontainer.DistinguishedName | foreach-object {
		$policy = $_.DistinguishedName
		write-verbose "[+] Policy $policy"
		$obj = get-adobject -property whenChanged,whenCreated,Name,objectClass  $policy
		if ( $obj.objectClass-eq 'msDS-PasswordSettings' ) { 
			$config = Get-ADFineGrainedPasswordPolicy -Identity $policy }
    		else {
        		write-verbose "[+] Cannot read data for $policy - access denied, perhaps?"
        		$config = New-Object PSCustomObject -Property @{ "error" = "noaccess"
           		}
    		}
    		$auditcount = (get-acl -Audit $policy |Select-Object -ExpandProperty audit).count
    		$denycount = (get-acl $policy | Select-Object -ExpandProperty access | Where-Object AccessControlType -NE 'Allow').count

    		[void]$output.Add((New-Object PSCustomObject -Property @{
        		"dn" = $policy;
        		"type" = "finegrained";
        		"name" = $config.Name;
        		"AppliesTo" = $config.AppliesTo; 
           		"ComplexityEnabled" = $config.ComplexityEnabled;
            		"LockoutDuration" = $config.LockoutDuration;
            		"LockoutObservationWindow" = $config.LockoutObservationWindow;
            		"LockoutThreshold" = $config.LockoutThreshold;
            		"MaxPasswordAge" = $config.MaxPasswordAge;
            		"MinPasswordAge" = $config.MinPasswordAge;
            		"MinPasswordLength" = $config.MinPasswordLength;
            		"PasswordHistoryCount" = $config.PasswordHistoryCount;
            		"Precedence" = $config.Precedence;
            		"ReversibleEncryptionEnabled" = $config.ReversibleEncryptionEnabled;
            		"whenChanged" = $obj.whenChanged;
            		"whenCreated" = $obj.whenCreated;
            		"objectClass" = $obj.ObjectClass;
            		"saclcount" = $auditcount;
            		"denycount" = $denycount;
            		"error" = $config.error

    		}))
	}

	set-location $cwd
	$output
}
 



function Main {
	if ( $lint ) {
		write-host "[!] Not Implemented Yet. Sorry"
		
	} else {
		GenerateReport | Export-Csv -NoTypeInformation -Path $outputlocation 
	}
}

Main
