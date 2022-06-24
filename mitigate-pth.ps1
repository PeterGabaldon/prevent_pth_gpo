#
# Pedro Gabaldon - 17/02/2022
#  
#
#
# ITRESIT - https://itresit.es/

# Mitigate PTH with UAC 

#Requires -RunAsAdministrator

# This script in intendeed for applying the UAC mitigations for PTH attacks automatically. Take a look at https://download.microsoft.com/download/7/7/a/77abc5bd-8320-41af-863c-6ecfb10cb4b9/mitigating%20pass-the-hash%20(pth)%20attacks%20and%20other%20credential%20theft%20techniques_english.pdf

# Oficially, Microsoft recommends 3 mitigations:
#    1. Protect high privileged accounts delegation.
#    2. Enable UAC (included built-in admin - RID 500) and prevent local accounts login from network.
#    3. Protect using Windows Firewall... (If it is possible use better Forti, Palo Alto,... or at least PfSense) :P

# This script is focused on part 2.

#
# Policies
#
# Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode                                 
#                                                                                                                     ----> Basically enables LUA
# Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account
#                                                                                                                      ----> The built-in Admin account (RID 500) is also affected by UAC
# Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network
#                                                                                                                      ----> Whatever is added to this policy cannot authenticate from network
# Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services
#                                                                                                                     ----> Whatever is added to this policy cannot logon via RDP
# Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Terminal Services
#                                                                                                                      ----> Whatver is added to this policy cannot logon via TS (Old RDP, for )
#

# INF

$GPO_CONTENT='[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeDenyRemoteInteractiveLogonRight = *S-1-5-113
SeDenyNetworkLogonRight = *S-1-5-113
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
'

# INI

$GPT_CONTENT='[General]
Version=2
displayName=New Group Policy Object
'

function checkADModule {
    if (Get-Module -ListAvailable ActiveDirectory) {
        return $true
    }

    return $false
}

function getSelectedOU {
    Write-Host "Listing all OUs in the domain:"

    $all_ou = (Get-ADOrganizationalUnit -Filter '*')

    foreach ($ou in $all_ou) {
        Write-Host ($ou | Format-Table Name, DistinguishedName | Out-String)
    }

    # TODO. Improvement, select by number insted of entering DN
    $ou = Read-Host -Prompt "Enter the DN of the selected OU"

    return $ou
}

function getComputersFile {
    $file_path = Read-Host -Prompt "Enter file path containing each computer DN to move line by line"

    $file = Get-Content $file_path

    return $file
}


function getComputersNamesFile {
    $file_path = Read-Host -Prompt "Enter file path containing each computer Name to apply the GPO line by name"

    $file = Get-Content $file_path

    return $file
}

function moveComputersToOU($ou) {
    $file = getComputersFile

    foreach ($line in $file) {
        Get-ADComputer "$line" | Move-ADObject -TargetPath $ou
    }
}

function applyGPOWithOU ($gpo) {    
    $ou = getSelectedOU

    $user_input = Read-Host -Prompt "Move list of computers from a file to the OU? (Y/N)"

    if ($user_input -eq "y" -or $user_input -eq "Y") {
        moveComputersToOU($ou)
    }

    $computers = Get-ADComputer -Filter * -SearchBase $ou

    Write-Host "The GPO will be applied to the following computers:"

    foreach ($computer in $computers) {
        Write-Host $computer.name
    }

    New-GPLink -Guid ($gpo | Select-Object -ExpandProperty Id) -Target $ou -LinkEnabled No
    Set-GPPermission -Guid ($gpo | Select-Object -ExpandProperty Id) -PermissionLevel GpoApply -TargetName "Domain Computers" -TargetType Group

    Write-Host "Link created but not enabled, check it before enabling!"
}

function applyGPOWithoutOU ($gpo) {
    Write-Host "The GPO will be linked to domain"
    Write-Host "Three options:"
    Write-Host "1. Add all the computers to the security filter"
    Write-Host "2. Create a group, add compputers to the group and then add that group to the security filter"
    Write-Host "3. Link To Domain"
    [int]$user_input = Read-Host -Prompt "1, 2 or 3"

    if ($user_input -eq 1) {
        $file = getComputersNamesFile        
        foreach ($line in $file) {
            Set-GPPermission -Guid ($gpo | Select-Object -ExpandProperty Id) -PermissionLevel GpoApply -TargetName $line -TargetType Computer
        }

    } elseif ($user_input -eq 2) {
        $file = getComputersNamesFile
        $new_grp_name = Read-Host -Prompt "Enter name of new group"
        New-ADGroup -Name $new_grp_name -GroupCategory Security -GroupScope Global -DisplayName $new_grp_name

        foreach ($line in $file) {
            Add-ADGroupMember -Identity $new_grp_name -Members "$line$"
        }

        Set-GPPermission -Guid ($gpo | Select-Object -ExpandProperty Id) -PermissionLevel GpoApply -TargetName $new_grp_name -TargetType Group
    } elseif ($user_input -eq 3) {
        Write-Host "It is recommend to install this WMI Filters https://github.com/darkoperator/powershell_scripts/blob/master/install-wmifilters.ps1"
        Write-Host "Link created but not enabled, check it before enabling!"
        Set-GPPermission -Guid ($gpo | Select-Object -ExpandProperty Id) -PermissionLevel GpoApply -TargetName "Domain Computers" -TargetType Group
    }
    
    New-GPLink -Guid ($gpo | Select-Object -ExpandProperty Id) -Target (Get-ADDomain | select -ExpandProperty DistinguishedName) -LinkEnabled No
}

function main {
    $adModule = checkADModule
    if (-not $adModule) {
        Write-Host "PowerShell module ActiveDirectory is not installed"
        Write-Host "Install RSAT: Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online"
        exit 1
    } else {
        Write-Host "PowerShell module installed, continuing..."
    }

    $gpo_name = Read-Host -Prompt "Enter the name for the new GPO"

    $new_gpo = New-GPO -Name $gpo_name -Comment "GPO to protect against lateral movements using local accounts"

    $ldif = "dn: $($new_gpo | Select-Object -ExpandProperty Path)
changetype: modify
add: gPCMachineExtensionNames
gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
-
"

    $tmp = New-TemporaryFile

    $ldif | Out-File -FilePath $tmp.FullName

    C:\Windows\System32\ldifde.exe -i -f $tmp.FullName

    $ldif = "dn: $($new_gpo | Select-Object -ExpandProperty Path)
changetype: modify
replace: versionNumber
versionNumber: 2
-
"

    $tmp = New-TemporaryFile

    $ldif | Out-File -FilePath $tmp.FullName

    C:\Windows\System32\ldifde.exe -i -f $tmp.FullName

    # Create inf and ini

    # Get INF path from Directory

    $filter = "(objectclass=*)"
    $RootOU = $new_gpo.Path

    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
    $Searcher.Filter = $Filter
    $Searcher.SearchScope = "Base" # Either: "Base", "OneLevel" or "Subtree"
    
    $path = "$($Searcher.FindAll().Properties.gpcfilesyspath)\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $path_gpt = "$($Searcher.FindAll().Properties.gpcfilesyspath)\GPT.INI"

    New-Item $path -Value $GPO_CONTENT -Force

    New-Item $path_gpt -Value $GPT_CONTENT -Force

    Set-GPPermission -Guid ($new_gpo | Select-Object -ExpandProperty Id) -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group

    Write-Host "Select Option:"
    Write-Host "1. Apply to OU"
    Write-Host "2. Apply without OU"

    [int]$user_input = Read-Host -Prompt "Select Option"

    while ($user_input -lt 1 -or $user_input -gt 2) {
        Write-Host "Invalid option"
        [int]$user_input = Read-Host -Prompt "Select Option. Enter any other number to exit"
    }

    if ($user_input -eq 1) {
        applyGPOWithOU($new_gpo)
    } elseif ($user_input -eq 2) {
        applyGPOWithoutOU($new_gpo)
    }

    # Write-Host "[IMPORTANT] Remember that HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy prevents token filtering if it set to 1, though effectively disabling UAC"
    # Write-Host "I can force it to be disabled via a Preference. Force it?"
}

main