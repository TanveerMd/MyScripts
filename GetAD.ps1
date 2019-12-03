Param($DC, $optfile)

"Script start ====="+$(Get-Date) | Out-File -filepath $optfile -append
"" | Out-File -filepath $optfile -append

$ErrorActionPreference = "Stop"
Try{
#Establishing persistent AD session remotely on a DC
#$ADSession = New-PSSession -ComputerName $DC -Credential (Get-Credential)
$ADSession = New-PSSession -ComputerName $DC
}
Catch{
	"Exception while establishing remote PS Session on "+$DC+ "| "+$_.Exception.Message | Out-File -filepath $optfile -append
}

If ($ADSession){
"Remote PS Session successfully established on "+$DC | Out-File -filepath $optfile -append

#Checking PS execution policy to check if the server allows remote execution
$execPol = Invoke-Command -Session $ADSession -ScriptBlock {Get-ExecutionPolicy} | select -ExpandProperty Value

If ($execPol -eq "RemoteSigned")
{
	"Execution policy on remote server is remote signed, no changes to PS execution policy" | Out-File -filepath $optfile -append
	"" | Out-File -filepath $optfile -append
}
Else
{
	"Changing '$execPol' execution policy to RemoteSigned"
	""
	Invoke-Command -Session $ADSession -ScriptBlock {Set-Executionpolicy -Executionpolicy RemoteSigned}
}

Function Invoke-ADPSModule
{
	$ErrorActionPreference = "Stop"
	Try{
		#Loading Active Directory PS Module in local machine
		Invoke-Command -ScriptBlock {Import-Module  -Name ActiveDirectory} -Session $ADSession
		Import-PSSession -Session $ADSession -Prefix REM -Module ActiveDirectory -AllowClobber | Out-Null
	}
	Catch{
		"Exception while importing AD PS module remotely | "+$_.Exception.Message
	}

}

Function Get-ForestDetails
{
	Try{
		""
		"::: FOREST details :::"
		"Forest Name: "+(Get-REMADForest).Name
		"Functional Level: "+(Get-REMADForest).ForestMode
		"Domains: "+(Get-REMADForest).Domains
		"Sites: "+(Get-REMADForest).Sites
		"GCs or DCs: "+(Get-REMADForest).GlobalCatalogs
		"Replica Directory Servers: "+(Get-REMADDomain).ReplicaDirectoryServers
		#"TombStoneLifeTime: "+(Get-REMADobject "cn=Directory Service,cn=Windows NT,cn=Services,cn=Configuration,dc=CASPER,dc=com" -Properties "tombstonelifetime").tombstonelifetime
		"TombStoneLifeTime: "+(Get-REMADobject "cn=Directory Service,cn=Windows NT,cn=Services,cn=Configuration,dc=Devops,dc=org" -Properties "tombstonelifetime").tombstonelifetime
	}
	Catch{
		"Exception while running remote AD PS commands to get Forest details | "+$_.Exception.Message
	}
}

Function Get-DomainDetails
{
	Try{
		""
		"::: Domain details :::"
		"Domain Name: "+(Get-REMADDomain).Name
		"Functional Level: "+(Get-REMADDomain).DomainMode
		"Master: "+(Get-REMADDomain).InfrastructureMaster
		"Replica Directory Servers: "+(Get-REMADDomain).ReplicaDirectoryServers
	}
	Catch{
		"Exception while running remote AD PS commands to get Domain details | "+$_.Exception.Message
	}
}


Function Get-DomainControllerDetails
{
	Try{
		""
		"::: Domain Controller details :::"
		"Domain Controller Name: "+(Get-REMADDomainController).HostName
		"DC IP v4 Address: "+(Get-REMADDomainController).IPv4Address
		"LDAP POrt: "+(Get-REMADDomainController).LdapPort
		"IsGlobalCatalog: "+(Get-REMADDomainController).IsGlobalCatalog
		"DC Roles: "+(Get-REMADDomainController).OperationMasterRoles
		"Disk space Report: "
		get-WmiObject win32_logicaldisk -ComputerName $DC -Filter "Drivetype=3"  |  ft SystemName,DeviceID,VolumeName,@{Label="Total Size(GB)";Expression={$_.Size / 1gb -as [int] }},@{Label="Free Size(GB)";Expression={$_.freespace / 1gb -as [int] }} -autosize 
		"Last Boot up time: "
		Get-CimInstance -ClassName win32_operatingsystem -ComputerName $DC | select csname, lastbootuptime
	}
	Catch{
		"Exception while running remote AD PS commands to get Domain Controller details | "+$_.Exception.Message
	}
}


Function Get-OUDetails
{
	Try{
		""
		"::: OU details :::"
		"OU Names: "+(Get-REMADOrganizationalUnit -Filter *).Name
		"Empty OUs: "+(Get-REMADOrganizationalUnit -Filter * | Where-Object {-not ( Get-REMADObject -Filter * -SearchBase $_.Distinguishedname -SearchScope OneLevel -ResultSetSize 5 )}).Name
		"ACLs "
		$OUs = (Get-REMADOrganizationalUnit -Filter *).Name
		Foreach($OU in $OUs){
		Invoke-Command -Session $ADSession -ScriptBlock {(Get-ACL $("AD:\"+(Get-ADOrganizationalUnit -filter "name -eq $OU").distinguishedname)).access | ft identityreference, accessControlType -a}
		}
	}
	Catch{
		"Exception while running remote AD PS commands to get OU details | "+$_.Exception.Message
	}
}


Function Get-ADSiteDetails
{
	""
	"::: Sites summary :::"
	$CurForestName = (Get-REMADForest).Name
	$a = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $CurForestName)
	[array]$ADSites=[System.DirectoryServices.ActiveDirectory.Forest]::GetForest($a).sites
	#$ADSites
	ForEach ($Site in $ADSites)
	{
		$SiteName = $Site.Name
		$SiteLocation = $site.Location
		$SiteOption = $Site.Options

		$SiteServers = $Site.Servers
		$SiteSubnets = $Site.Subnets
		$SiteLinks = $Site.SiteLinks

		"Site Name: "+$SiteName
		If ($SiteLocation){
		"Site Location: "+$SiteLocation
		}
		Else{
		"Site Location: Not available"
		}
		If ($SiteOptions){
		"Site Options: "+$SiteOptions
		}
		Else{
		"Site Options: Not available"
		}
		If ($SiteSubnets){
		"Site Subnets: "+$SiteSubnets
		}
		Else{
		"Site Subnets: Not available"
		}
		"Site Servers: "+$SiteServers
		"Site Links: "+$SiteLinks
	}

}

Function Get-PatchDetails
{
	Try{
		""
		"::: Patching details :::"

		$comps = Get-REMADComputer -Filter * | select -ExpandProperty name

		foreach ($comp in $comps)
		{
			
			If(Test-Connection $comp -Count 1 -Quiet)
			{

				$ErrorActionPreference = "Stop"
				Try{
				$ptch = gwmi -Class win32_quickfixengineering -ComputerName $comp | Sort-Object InstalledOn -Descending | select HotFixID, InstalledOn | select -First 3 | ft -a
				If($ptch){
					$comp
					$ptch
				}
				Else{
					$comp+" | No patches applied or found on"
				}
				}
				Catch{
					$comp+" | "+$_.Exception.Message
				}		
			}
			Else
			{
				$comp + " | Not reachable"
			}
		}
	}
	Catch{
		"Unable to get patch details, please check previous errors"
	}
}


#Calling functions
Invoke-ADPSModule | Out-File -filepath $optfile -append

Get-ForestDetails | Out-File -filepath $optfile -append
Get-OUDetails | Out-File -filepath $optfile -append
Get-ADSiteDetails | Out-File -filepath $optfile -append
Get-DomainDetails | Out-File -filepath $optfile -append
Get-DomainControllerDetails | Out-File -filepath $optfile -append
#Get-PatchDetails | Out-File -filepath $optfile -append


#Closing Active Directory remote PS Session
Remove-PSSession -Session $ADSession
$ADSessionState = $ADSession.State


If($ADSessionState -ne "Closed")
{
	"" | Out-File -filepath $optfile -append
	"Remote AD PS Session is still available, current state is '$ADSessionState'" | Out-File -filepath $optfile -append
}
Else
{
	"" | Out-File -filepath $optfile -append
	"Remote AD PS Session is '$ADSessionState'" | Out-File -filepath $optfile -append
}


"" | Out-File -filepath $optfile -append
"Script end ====="+$(Get-Date) | Out-File -filepath $optfile -append
"" | Out-File -filepath $optfile -append

	}
Else{
	"Script aborted without calling any functions" | Out-File -filepath $optfile -append
	"" | Out-File -filepath $optfile -append
	"Script end ====="+$(Get-Date) | Out-File -filepath $optfile -append
	"" | Out-File -filepath $optfile -append
}