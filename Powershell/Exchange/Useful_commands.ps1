#Uncomment each command as required
 
#List all Distribution Lists and Groups
#Get-DistributionGroup | fl name

#List Dynamic Distribution Lists and Groups
#Get-DynamicDistributionGroup | fl name,recipientfilter

#All subscribers are members
#Not all members are subscribers
 

#Add a user as a member only:
#Add-UnifiedGroupLinks -Identity GROUP -LinkType Members -Links user@email.com

#Add a user as a member or subscriber, and/or change a member to a member+subscriber
#Add-UnifiedGroupLinks -Identity GROUP -LinkType Subscribers -Links user@email.com

#Remove a user from the group:
#Remove-UnifiedGroupLinks -Identity GROUP -LinkType Members -Links user@email.com

#Remove a subscription, but not a membership
#Remove-UnifiedGroupLinks -Identity GROUP -LinkType Subscribers -Links user@email.com

#List group subscribers
#Get-UnifiedGroupLinks slt@williams.uk.com -LinkType Subscriber

#Get-OrganizationConfig
#Set-OrganizationConfig -FocusedInboxOn $false
#Set-OrganizationConfig -FocusedInboxOn $true