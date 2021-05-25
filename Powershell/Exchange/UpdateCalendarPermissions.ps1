#Owner — gives full control of the mailbox folder: read, create, modify, and delete all items and folders. Also, this role allows to manage item’s permissions;
#PublishingEditor — read, create, modify, and delete items/subfolders (all permissions, except the right to change permissions);
#Editor — read, create, modify, and delete items (can’t create subfolders);
#PublishingAuthor — create, read all items/subfolders. You can modify and delete only items you create;
#Author — create and read items; edit and delete own items;
#NonEditingAuthor – full read access, and create items. You can delete only your own items;
#Reviewer — read folder items only;
#Contributor — create items and folders (can’t read items);
#AvailabilityOnly — read Free/Busy info from the calendar;
#LimitedDetails;
#None — no permissions to access folder and files.

#$LiveCred = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $LiveCred -Authentication Basic –AllowRedirection
#Import-PSSession $Session
#Set-ExecutionPolicy RemoteSigned

#show current permissions
#Get-MailboxFolderPermission -Identity EMAIL@EVILCORP.COM:\calendar

#add calendar permission
#Add-MailboxFolderPermission -Identity EMAIL@EVILCORP.COM:\calendar -user EMAIL@EVILCORP.COM -AccessRights Reviewer

#remove calendar permission
#Remove-MailboxFolderPermission -Identity EMAIL@EVILCORP.COM:\calendar –user EMAIL@EVILCORP.COM