# Willaims and Co IT Team Utility Suite
# Created by Daniel Pickering

########## REQUIRED POWERSHELL MODULES BELOW ##########

#Install-Module -Name Microsoft.Online.SharePoint.PowerShell -RequiredVersion 16.0.8029.0
#Install-Module MSOnline

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{

###################################################### FIND RDP USER #############################################################

######## FIND RDP USER MENU ########

Function FindUserRDP
{
Clear-Host
do {
     Clear-Host
     Write-Host -Object ' __        ____   ______  _____  ' -ForegroundColor Yellow
     Write-Host -Object ' \ \      / /\ \ / / ___|| ____| ' -ForegroundColor Yellow
     Write-Host -Object '  \ \ /\ / /  \ V /\___ \|  _|   ' -ForegroundColor Yellow
     Write-Host -Object '   \ V  V /    | |  ___) | |___  ' -ForegroundColor Yellow
     Write-Host -Object '    \_/\_/     |_| |____/|_____| ' -ForegroundColor Yellow                          
     Write-Host -Object ''
     Write-Host -Object '*********************************'
     Write-Host -Object '     Find Logged On RDP User' -ForegroundColor Yellow
     Write-Host -Object '*********************************'
     Write-Host -Object ''
     Write-Host -Object ' Q.  Return To Previous Menu'
     Write-Host -Object ''
     $username = Read-Host -Prompt ' Enter Username'
     Write-Host -Object ' Searching....' -ForegroundColor Green
     switch ($username)
     {
            Q 
            {
                Menu
            }
            default
            {
                FindRDP
            }
        }
    }
    until ($username -eq 'q')
}

######## FIND RDP USER AND PRINT TO SCREEN ########

Function FindRDP {
#Get all Servers' names in the Domain that are not enabled.
$serverList=(Get-ADComputer -Filter ('(Name -Like "*COMPUTERNAME*") -AND (Enabled -Eq "True")') | select-object Name).Name

#Start a foreach cycle which will go through each Server in the ServerList
foreach ($Server in $serverList)
	{
		#Ping the Server
		$ping = Test-Connection $Server -Count 1 -EA Silentlycontinue

		#If Ping is successfull then keep going
		if($ping)
		{
			#Get server session ID if $username is logged on - cmd /c is needed for the 2>NUL to avoid quser to write "No User exists for *" when nobody is logged on a server.
			$sessionID = ((cmd /c quser /server:$server "2>NUL"| ? { $_ -match $username }) -split ' +')[2]
			
			#If sessionsID exists, write it to console (ie: rdp-tcp#1)
			while ($sessionID -Like "*rdp*")
			{

                    $foundUser = "$($username) is logged on $($Server) with ID: $($sessionID)"
                    break
            }
	    }
	}
Write-Host ""
Write-Host $foundUser
pause
}

############################################################## FIND NON RDP USER ##########################################################

######## FIND NON RDP USER MENU ########

Function FindUser{
Clear-Host
do {
     Clear-Host
     Write-Host -Object '          _____     ____  ' -ForegroundColor Green
     Write-Host -Object '         /      \  |  o | ' -ForegroundColor Green
     Write-Host -Object '        |        |/ ___\| ' -ForegroundColor Green
     Write-Host -Object '        |_________/       ' -ForegroundColor Green
     Write-Host -Object '        |_|_| |_|_|       ' -ForegroundColor Green
     Write-Host -Object ''
     Write-Host -Object '*********************************'
     Write-Host -Object '    Find Logged On User (SLOW)' -ForegroundColor Yellow
     Write-Host -Object '*********************************'
     Write-Host -Object ''
     Write-Host -Object ' Q.  Return To Previous Menu'
     Write-Host -Object ''
     $username = Read-Host -Prompt ' Enter Username'
     Write-Host -Object ' Searching....' -ForegroundColor Green
     switch ($username)
     {
            Q 
            {
                MainMenu
            }
            default
            {
                Find
            }
        }
    }
    until ($username -eq 'q')
}

######## FIND NON RDP USER AND PRINT TO SCREEN ########

Function Find {
#Get all Servers' names in the Domain that are enabled.
$serverList=(Get-ADComputer -Filter ('(Name -NotLike "*COMPUTERNAME*") -AND (Name -NotLike "*COMPUTERNAME*") -AND (Name -NotLike "*COMPUTERNAME*") -AND (Enabled -Eq "True")') | select-object Name).Name

#Start a foreach cycle which will go through each Server in the ServerList
foreach ($Server in $serverList)
	{
		#Ping the Server
		$ping = Test-Connection $Server -Count 1 -EA Silentlycontinue

		#If Ping is successfull then keep going
		if($ping)
		{
			#Get server session ID if $username is logged on - cmd /c is needed for the 2>NUL to avoid quser to write "No User exists for *" when nobody is logged on a server.
			$sessionID = ((cmd /c quser /server:$server "2>NUL"| ? { $_ -match $username }) -split ' +')[2]
			
			#While sessionsID exists, write it to console but exclude any live RDP connection or console (ie: rdp-tcp#1)
            while($sessionID -Like "*console*")
			{
                    $foundUser = " $($username) is logged on $($Server) with ID: $($sessionID)"
                    break
            }
	    }
	}
Write-Host ""
Write-Host $foundUser
pause
}

################################################################### EXPORT LOCAL AD TO FILE AND IMPORT TO M365 ###################################################################################

$filePath = "C:\Scripts\AD_Export_to_M365\AllADUsers.csv" #CHANGEME

######## EXPORT ALL AD USERS INFO ########
Function Local-All 
{
    Set-ExecutionPolicy RemoteSigned
    Import-Module ActiveDirectory
    Clear-Host
    Write-Host -Object ' Exporting....' -ForegroundColor Green
    Get-ADUser -Filter {(Name -NotLike "*USERNAME*") -And (Mail -Like "*@*") -And (Name -NotLike "*USERNAME*") -And (Name -NotLike "*USERNAME*") -And (Name -NotLike "*USERNAME*") -And (Mail -NotLike "EMAIL@EMAIL.COM") -And (Mail -NotLike "EMAIL@EMAIL.COM") -And (Name -NotLike "USERNAME") -And (Name -NotLike "USERNAME*") -And (Name -NotLike "*USERNAME*") -And (Name -NotLike "*USERNAME*")} -Properties * |
     Select -Property mail,l,co,Department,displayName,givenName,sn,mobile,Office,telephoneNumber,postalCode,st,streetAddress,title | Sort-Object Department -Descending | Export-CSV $filePath -NoTypeInformation -Encoding UTF8
    Write-Host -Object ' Complete.' -ForegroundColor Green
    Write-Host -Object ' Location: $filePath' -ForegroundColor Green
    Write-Host ' Location: '$filePath -ForegroundColor Green
    pause
}

######## EXPORT SINGLE USER INFO ########

Function Local-Single
{
    Set-ExecutionPolicy RemoteSigned
    Import-Module ActiveDirectory
    Clear-Host
    $email = Read-Host -Prompt ' Enter User email address'
    Write-Host -Object ' Exporting.' -ForegroundColor Green
    Get-ADUser -Filter {(mail -Like $email)} -Properties * | Select -Property mail,l,co,Department,displayName,givenName,sn,mobile,Office,telephoneNumber,postalCode,st,streetAddress,title | Sort-Object Department -Descending |
     Export-CSV $filePath -NoTypeInformation -Encoding UTF8
    Write-Host -Object ' Complete.' -ForegroundColor Green
    Write-Host ' Location: '$filePath -ForegroundColor Green
    pause
}

######## IMPORT INFO TO M365 ########

Function Import-M365
{
    Set-ExecutionPolicy RemoteSigned
    Connect-MSolService
    Clear-Host
    Write-Host -Object ' Importing....' -ForegroundColor Green
    Import-Csv $filePath | 
    foreach{Set-MsolUser -UserPrincipalName $_.mail -City $_.l -Country $_.co -Department $_.Department -DisplayName $_.displayName -FirstName $_.givenName -LastName $_.sn -MobilePhone $_.mobile -Office $_.Office -PhoneNumber $_.telephoneNumber -PostalCode $_.postalCode -State $_.st -streetAddress $_.StreetAddress -Title $_.title}
    Write-Host -Object ' Complete.' -ForegroundColor Green
    pause
}

######## LOCAL AD TO M365 MENU ########
    
Function ADMicrosoft 
{
    Clear-Host       
    Do
    {
        Clear-Host
        Write-Host -Object '     _    ____        __    _____  __  ____  ' -ForegroundColor Cyan
        Write-Host -Object '    / \  |  _ \       \ \  |___ / / /_| ___| ' -ForegroundColor Cyan
        Write-Host -Object "   / _ \ | | | |  _____\ \   |_ \| '_ \___ \ " -ForegroundColor Cyan
        Write-Host -Object '  / ___ \| |_| | |_____/ /  ___) | (_) |__) |' -ForegroundColor Cyan
        Write-Host -Object ' /_/   \_\____/       /_/  |____/ \___/____/ ' -ForegroundColor Cyan
        Write-Host -Object ''
        Write-Host -Object '*********************************************'
        Write-Host -Object '           Copy User Info to M365            ' -ForegroundColor Cyan
        Write-Host -Object '*********************************************'
        Write-Host -Object ' 1.  Export all users from LOCAL AD   '
        Write-Host -Object ''
        Write-Host -Object ' 2.  Export Single user from LOCAL AD '
        Write-Host -Object ''
        Write-Host -Object ' 3.  Import User/s into M365 '
        Write-Host -Object ''
        Write-Host -Object ' Q.  Return To Previous Menu'
        Write-Host -Object $errout
        $MenuAD2M365 = Read-Host -Prompt '(1-3 or Q to Quit)'
 
        switch ($MenuAD2M365) 
        {
            1 
            {
                Local-All
            }
            2 
            {
                Local-Single
            }
            3 
            {
                Import-M365
            }
            Q 
            {
                M365Menu
            }   
            default
            {
                $errout = ' Invalid option please try again........Try 1-3 or Q only'
            }
 
        }
    }
    until ($MenuAD2M365 -eq 'q')
}

######################################### Exchange Administration ########################################

######## Connect to Exchange ########

Function ConnectExch
{
    Clear-Host
    $LiveCred = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $LiveCred -Authentication Basic –AllowRedirection
    Import-PSSession $Session
    Set-ExecutionPolicy RemoteSigned
}


######## List Exchange Permissions ########

Function ListPermDefs
{
    Clear-Host        
    Do
    {
        Clear-Host
        Write-Host -Object " ____                     _         _                 "-ForegroundColor Cyan
        Write-Host -Object "|  _ \ ___ _ __ _ __ ___ (_)___ ___(_) ___  _ __  ___ "-ForegroundColor Cyan
        Write-Host -Object "| |_) / _ \ '__| '_ ` _ \| / __/ __| |/ _ \| '_ \/ __|"-ForegroundColor Cyan
        Write-Host -Object "|  __/  __/ |  | | | | | | \__ \__ \ | (_) | | | \__ \"-ForegroundColor Cyan
        Write-Host -Object "|_|   \___|_|  |_| |_| |_|_|___/___/_|\___/|_| |_|___/"-ForegroundColor Cyan
        Write-Host -Object ''
        Write-Host -Object '******************************************************'
        Write-Host -Object '            Exchange Permissions Explained            ' -ForegroundColor Cyan
        Write-Host -Object '******************************************************'                    
        Write-Host -Object "Owner — gives full control of the mailbox folder: read, create, modify, and delete all items and folders. Also, this role allows to manage item’s permissions"
        Write-Host -Object ''
        Write-Host -Object "PublishingEditor — read, create, modify, and delete items/subfolders (all permissions, except the right to change permissions)"
        Write-Host -Object ''
        Write-Host -Object "Editor — read, create, modify, and delete items (can’t create subfolders)"
        Write-Host -Object ''
        Write-Host -Object "PublishingAuthor — create, read all items/subfolders. You can modify and delete only items you create"
        Write-Host -Object ''
        Write-Host -Object "Author — create and read items; edit and delete own items"
        Write-Host -Object ''
        Write-Host -Object "NonEditingAuthor – full read access, and create items. You can delete only your own items"
        Write-Host -Object ''
        Write-Host -Object "Reviewer — read folder items only"
        Write-Host -Object ''
        Write-Host -Object "Contributor — create items and folders (can’t read items)"
        Write-Host -Object ''
        Write-Host -Object "AvailabilityOnly — read Free/Busy info from the calendar"
        Write-Host -Object ''
        Write-Host -Object "LimitedDetails"
        Write-Host -Object ''
        Write-Host -Object "None — no permissions to access folder and files"
        Write-Host -Object $errout
        $MenuPerm = Read-Host -Prompt '(Q to Quit)'
        switch ($MenuPerm) 
        {
            Q 
            {
                ExchangeCal
            }
            default
            {
                $errout = ' Invalid option please try again........Try 1-5 or Q only'
            }
        }
    }
    until ($MenuPerm -eq 'q')
}

######## List Calendar Permissions for User ########

Function ListUserPerms{
    Clear-Host
    $userPermList = Read-Host -Prompt ' Enter User email address '
    Get-MailboxFolderPermission -Identity $userPermList':\calendar'
    pause
}

######## Add Calendar Permissions to an account ########

Function AddPerms{
    Clear-Host
    $userParent = Read-Host -Prompt ' Enter parent email address '
    $userChild = Read-Host -Prompt ' Enter child email address '
    Do{
        Write-Host -Object '******************************'
        Write-Host -Object '  Select Permission to grant  '
        Write-Host -Object '******************************'
        Write-Host -Object '1.  Owner'
        Write-Host -Object '2.  PublishingEditor'
        Write-Host -Object '3.  Editor'
        Write-Host -Object '4.  PublishingAuthor'
        Write-Host -Object '5.  Author'
        Write-Host -Object '6.  NonEditingAuthor'
        Write-Host -Object '7.  Reviewer'
        Write-Host -Object '8.  Contributor'
        Write-Host -Object '9.  AvailabilityOnly'
        Write-Host -Object '10. LimitedDetails'
        Write-Host -Object '11. None'
        Write-Host -Object $errout
        $PermList = Read-Host -Prompt '(Q to Quit)'
    switch ($PermList)
    {
        Q
        {
            ExchangeCal
        }
        1
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights Owner
            pause
            $PermList ='q'
        }
        2
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights PublishingEditor
            pause
            $PermList ='q'
        }
        3
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights Editor
            pause
            $PermList ='q'
        }
        4
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights PublishingAuthor
            pause
            $PermList ='q'
        }
        5
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights Author
            pause
            $PermList ='q'
        }
        6
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights NonEditingAuthor
            pause
            $PermList ='q'
        }
        7
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights Reviewer
            pause
            $PermList ='q'
        }
        8
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights Contributor
            pause
            $PermList ='q'
        }
        9
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights AvailabilityOnly
            pause
            $PermList ='q'
        }
        10
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights LimitedDetails
            pause
            $PermList ='q'
        }
        11
        {
            Add-MailboxFolderPermission -Identity $userParent':\calendar' -user $userChild -AccessRights None
            pause
            $PermList ='q'
        }
        default
        {
            $errout = ' Invalid option please try again........Try 1-11 or Q only'
        }
    }
    }
    Until ($PermList -eq 'q')
}

######## Delete calendar permissions from an account ########

Function DelPerms
{
    Clear-Host
    $userParent = Read-Host -Prompt ' Enter parent email address '
    $userChild = Read-Host -Prompt ' Enter child email address '
    $confirmation = Read-Host 'You are deleting permissions for ' $userChild ' on ' $userParent ' Correct? Y/N '
    if ($confirmation -eq 'y')
    {
        Remove-MailboxFolderPermission -Identity $userParent':\calendar' –user $userChild
        pause
    }
    else
    {
        DelPerms
    }
}

######## Calendar Exchange Main Menu ########

Function ExchangeCal
{
    Clear-Host        
    Do
    {
        Clear-Host
        Write-Host -Object '        _______  ______ _   _         ' -ForegroundColor Cyan
        Write-Host -Object '       | ____\ \/ / ___| | | |        ' -ForegroundColor Cyan
        Write-Host -Object '       |  _|  \  / |   | |_| |        ' -ForegroundColor Cyan
        Write-Host -Object '       | |___ /  \ |___|  _  |        ' -ForegroundColor Cyan
        Write-Host -Object '       |_____/_/\_\____|_| |_|        ' -ForegroundColor Cyan
        Write-Host -Object ''
        Write-Host -Object '**************************************'
        Write-Host -Object '   Exchange Calendar Administration   ' -ForegroundColor Cyan
        Write-Host -Object '**************************************'
        Write-Host -Object ' 1.  Connect and store credentials    '
        Write-Host -Object ''
        Write-Host -Object ' 2.  List Calendar Permissions and Definitions '
        Write-Host -Object ''
        Write-Host -Object ' 3.  List Calendar Permissions for User '
        Write-Host -Object ''
        Write-Host -Object ' 4.  Add Calendar Permission for User '
        Write-Host -Object ''
        Write-Host -Object ' 5.  Remove Calendar Permission for User'
        Write-Host -Object ''
        Write-Host -Object ' Q.  Return To Previous Menu'
        Write-Host -Object $errout
        $MenuExch = Read-Host -Prompt '(1-5 or Q to Quit)'
 
        switch ($MenuExch) 
        {
            1 
            {
                ConnectExch
            }
            2 
            {
                ListPermDefs
            }
            3 
            {
                ListUserPerms
            }
            4 
            {
                AddPerms
            }
            5 
            {
                DelPerms
            }
            Q 
            {
                M365Menu
            }   
            default
            {
                $errout = ' Invalid option please try again........Try 1-5 or Q only'
            }
 
        }
    }
    until ($MenuExch -eq 'q')
  }

######## GET ONEDRIVE USAGE ########

Function OneDrive
{
    Clear-Host
    Write-Host -Object "                .-~~~-.             " -ForegroundColor Cyan
    Write-Host -Object "        .- ~ ~-(       )_ _         " -ForegroundColor Cyan
    Write-Host -Object "      /                     ~ -.    " -ForegroundColor Cyan
    Write-Host -Object "     |                           \  " -ForegroundColor Cyan
    Write-Host -Object "      \                         .'  " -ForegroundColor Cyan
    Write-Host -Object "        ~- . _____________ . -~     " -ForegroundColor Cyan
    #Variable for SharePoint Online Admin Center URL
    $AdminSiteURL="https://YOURCOMPANY.sharepoint.com/"
    $CSVFile = "C:\Scripts\OneDrives.csv"
  
    #Connect to SharePoint Online Admin Center
    Connect-SPOService -Url $AdminSiteURL -credential (Get-Credential)
 
    #Get All OneDrive Sites usage details and export to CSV
    Write-Host -Object ' Exporting.' -ForegroundColor Green
    Get-SPOSite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/'" | Select URL, Owner, StorageQuota, StorageUsageCurrent, LastContentModifiedDate | Export-Csv -Path $CSVFile -NoTypeInformation
    Write-Host -Object ' Complete.' -ForegroundColor Green
    Write-Host ' Location: '$CSVFile -ForegroundColor Green
    pause
}

######## Export Mailboxes to CSV ########

Function ExportMailboxes
{
    Clear-Host
    $LiveCred = Get-Credential
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $LiveCred -Authentication Basic –AllowRedirection
    Import-PSSession $Session -DisableNameChecking
    Set-ExecutionPolicy RemoteSigned
    $mailExport = "C:\Scripts\Mailboxes.csv"
    Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited | where {$_.PrimarySmtpAddress -notlike '*MAIL@MAIL.COM' -And $_.DisplayName -notlike 'Discovery Search Mailbox' -And $_.DisplayName -notlike 'Audits' -And $_.DisplayName -notlike 'NAME' -And $_.DisplayName -notlike 'NAME' -And $_.DisplayName -notlike 'NAME'} | Select-Object DisplayName, PrimarySmtpAddress | Sort-Object PrimarySmtpAddress | Export-Csv -Path $mailExport -NoTypeInformation -Encoding UTF8
    Write-Host -Object ' Complete.' -ForegroundColor Green
    Write-Host ' Location: '$mailExport -ForegroundColor Green
    pause
    Remove-PSSession $Session
}

######## Out Emplyee Directory ########

## Call External Script ##

Function OutED
{
    Clear-Host
    $PSScriptRoot
    $ScriptToRun = $PSScriptRoot+"\OutED.ps1"
    &$ScriptToRun
}

################################ M365 Administration Menu ################################

Function M365Menu
{
    Clear-Host        
    Do
    {
        Clear-Host
        Write-Host -Object '        __  __ _____  __  ____        ' -ForegroundColor Cyan
        Write-Host -Object '       |  \/  |___ / / /_| ___|       ' -ForegroundColor Cyan
        Write-Host -Object "       | |\/| | |_ \| '_ \___ \       " -ForegroundColor Cyan
        Write-Host -Object '       | |  | |___) | (_) |__) |      ' -ForegroundColor Cyan
        Write-Host -Object '       |_|  |_|____/ \___/____/       ' -ForegroundColor Cyan
        Write-Host -Object ''
        Write-Host -Object '**************************************'
        Write-Host -Object '        Copy User Info to M365        ' -ForegroundColor Cyan
        Write-Host -Object '**************************************'
        Write-Host -Object ' 1.  Local AD User Info to M365       '
        Write-Host -Object ''
        Write-Host -Object ' 2.  Exchange Calendar Administration '
        Write-Host -Object ''
        Write-Host -Object ' 3.  Export OneDrive Usage to CSV     '
        Write-Host -Object ''
        Write-Host -Object ' 4.  Export List of Mailboxes to CSV  '
        Write-Host -Object ''
        Write-Host -Object ' Q.  Return To Previous Menu'
        Write-Host -Object $errout
        $Menu365 = Read-Host -Prompt '(1-4 or Q to Quit)'
 
        switch ($Menu365) 
        {
            1 
            {
                ADMicrosoft
                pause
            }
            2 
            {
                ExchangeCal
            }
            3 
            {
                OneDrive
            }
            4
            {
                ExportMailboxes
            }
            Q 
            {
                MainMenu
            }   
            default
            {
                $errout = ' Invalid option please try again........Try 1-4 or Q only'
            }
 
        }
    }
    until ($Menu365 -eq 'q')
}

########################################### MAIN MENU #############################################################

Function MainMenu 
{
    Clear-Host        
    Do
    {
        Clear-Host
        Write-Host -Object ' _   _ _   _ _ _ _   _           ' -ForegroundColor Yellow
        Write-Host -Object '| | | | |_(_) (_) |_(_) ___  ___ ' -ForegroundColor Yellow
        Write-Host -Object '| | | | __| | | | __| |/ _ \/ __|' -ForegroundColor Yellow
        Write-Host -Object '| |_| | |_| | | | |_| |  __/\__ \' -ForegroundColor Yellow
        Write-Host -Object ' \___/ \__|_|_|_|\__|_|\___||___/' -ForegroundColor Yellow                                                                                                
        Write-Host -Object ''
        Write-Host -Object '*********************************'
        Write-Host -Object '     Useful Powershell Tools' -ForegroundColor Yellow
        Write-Host -Object '*********************************'
        Write-Host -Object ' 1.  Find Logged On RDP User '
        Write-Host -Object ''
        Write-Host -Object ' 2.  Find Logged On User (SLOW)'
        Write-Host -Object ''
        Write-Host -Object ' 3.  Update Employee Directory'
        Write-Host -Object ''
        Write-Host -Object ' 4.  Office 365 Administration'
        Write-Host -Object ''
        Write-Host -Object ' Q.  Quit'
        Write-Host -Object $errout
        $Menu = Read-Host -Prompt '(1-4 or Q to Quit)'
 
        switch ($Menu) 
        {
            1 
            {
                FindUserRDP
            }
            2 
            {
                FindUser
            }
            3 
            {
                OutED
            }
            4
            {
                M365Menu
            }
            Q 
            {
                Exit
            }   
            default
            {
                $errout = ' Invalid option please try again........Try 1-4 or Q only'
            }
 
        }
    }
    until ($Menu -eq 'q')
}   
 
# Launch The Menu

MainMenu
}
else{
    Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
}
