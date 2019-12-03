[xml]$UsersDet = Get-Content UserList.xml

$strSenderTag = "//users/sender"
$strUserTag = "//users/user"
$strSMTPTag = "//users/SMTPServer"

$item1 = Select-XML -Xml $UsersDet -XPath $strSenderTag

If ($item1 -eq $Null -Or [string]::IsNullOrEmpty($UsersDet.users.sender.Email) -Or [string]::IsNullOrEmpty($UsersDet.users.sender.Name))
{
	Write-host "Problem found in "$strSenderTag" tag. `r`nPlease check the XPath, it can be missing or mispelled `r`nPlease check if there are any missed attributes" -fore yellow
}
Else
{
	Write-host "Sender tag == " $item1
}

$item2 = Select-XML -Xml $UsersDet -XPath $strUserTag

If ($item2 -eq $null)
{
	Write-host "Problem found in "$strUserTag" tag. `r`nPlease check the XPath, it can be missing or mispelled `r`nPlease check if there are any missed attributes" -fore yellow
}
Else
{
	Write-host "User tag == " $item2

	Foreach ($user in $UsersDet.users.user)

	{

		If ([string]::IsNullOrEmpty($user.Email) -Or [string]::IsNullOrEmpty($user.Name))
		{
			Write-host "Problem found in "$strUserTag" tag. `r`nPlease check the XPath, it can be missing or mispelled `r`nPlease check if there are any missed attributes" -fore yellow
		}
		Else
		{
			Write-host $user.Name
			Write-host $user.Email
		}
	}
}

$item3 = Select-XML -Xml $UsersDet -XPath $strSMTPTag

If ($item3 -eq $null -Or [string]::IsNullOrEmpty($UsersDet.users.SMTPServer.Port) -Or [string]::IsNullOrEmpty($UsersDet.users.SMTPServer.FQDN))
{
	Write-host "Problem found in "$strSMTPTag" tag. `r`nPlease check the XPath, it can be missing or mispelled `r`nPlease check if there are any missed attributes" -fore yellow
}
Else
{
	Write-host "SMTP tag == " $item3
}