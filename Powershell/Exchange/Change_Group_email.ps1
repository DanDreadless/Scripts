#Connect to your Exchange Online Powershell using a Global Administrator accoun

#Run the below commands to add required SMTP addresses as an alias:

Set-UnifiedGroup -Identity "EMAIL@EVILCORP.COM" -EmailAddresses: @{Add ="EMAIL@EVILCORP.COM"}

Set-UnifiedGroup -Identity "EMAIL@EVILCORP.COM" -EmailAddresses: @{Add ="EMAIL@EVILCORP.onmicrosoft.com"}

#Promote alias as a primary SMTP address using this command:

Set-UnifiedGroup -Identity "EMAIL@EVILCORP.COM" -PrimarySmtpAddress "EMAIL@EVILCORP.COM"

#If you no longer want to associate the old address with the group, you can remove it by running these commands:

Set-UnifiedGroup -Identity "EMAIL@EVILCORP.COM" -EmailAddresses: @{Remove="EMAIL@EVILCORP.onmicrosoft.com"}

Set-UnifiedGroup -Identity "EMAIL@EVILCORP.COM" -EmailAddresses: @{Remove="EMAIL@EVILCORP.COM"}