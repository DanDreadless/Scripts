#Change the $group variable to point to the group you want to query

$group = "GROUP NAME HERE"
Get-Recipient -RecipientPreviewFilter (Get-DynamicDistributionGroup $group).RecipientFilter >> C:\OUTPUT\DIRECTORY\users.txt