#Reading users from XML file
[xml]$UsersDet = Get-Content UserList.xml

$strSMTP = $UsersDet.users.SMTPServer.FQDN
$iPort = $UsersDet.users.SMTPServer.Port

Write-Host "SMTP Server : "$strSMTP
Write-Host "SMTP Port : "$iPort

If ($UsersDet.users."*"."*" -eq $Null)
{

Write-Host "Null sender found" -fore red

}

$strSenderE = $UsersDet.users.sender.Email
$strSenderN = $UsersDet.users.sender.Name

Write-Host "Sender Name : "$strSenderN
Write-Host "Sender email : "$strSenderE

Foreach ($user in $UsersDet.users.user)

{
	Write-Host "Email : " $user.Email
	Write-Host "Name : "$user.Name
}