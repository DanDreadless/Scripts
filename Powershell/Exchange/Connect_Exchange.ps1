#Change UserPrincipalName to your M365 username

Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName M365-USERNAME -ShowProgress $true