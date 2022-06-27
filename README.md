# AD Lateral Movements Hardening

## Intro

This script in intendeed for applying the UAC mitigations for PTH attacks automatically. Take a look at https://download.microsoft.com/download/7/7/a/77abc5bd-8320-41af-863c-6ecfb10cb4b9/mitigating%20pass-the-hash%20(pth)%20attacks%20and%20other%20credential%20theft%20techniques_english.pdf

Oficially, Microsoft recommends 3 mitigations:
   1. Protect high privileged accounts delegation.
   2. Enable UAC (included built-in admin - RID 500) and prevent local accounts login from network.
   3. Protect using Windows Firewall... (If it is possible use better Forti, Palo Alto,... or at least PfSense) :P

This script is focused on part 2.

# Policies

| Policy                                                                                                                                                                     | Result                                                                   |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode              | Basically enables LUA                                                    |
| Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account | The built-in Admin account (RID 500) is also affected by UAC             |
| Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network                              | Whatever is added to this policy cannot access the computer from network |
| Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services                                | Whatever is added to this policy cannot logon via RDP                    |

# Explanation

First policy: UAC prevents lateral movements using **LOCAL** accounts because it is neccesary a high mandatory integrity level for remote execution, for example: openening SCManager for creating and running a service remotely requieres admin rights (smbexec, psexec...), opening Task Scheduler Remotely (atexec), WinRM... With UAC enabled you will get a medium integrity level when authenticating, therefore failing to execute code remotely.

Second Policy: In a default environment, Built-In Administrator is not affected by UAC. Then, if computers in the network share the same Administrator password (Unfortunately, this is the case in most environments) you can move laterally. Enabling that the Built-In Administrator is also affected by UAC is recommended because it will be affected the same way as the rest of administratot accounts (First Policy's explanation).

Third and Fourth Policies: The Third Policy can prevent login/accessing the computer from the network. It is recommended to block Local Accounts (SID S-1-5-113) from accessing the computer from the network. The Fourth Policy applies only for RDP Interactive Logons.

This does not prevent Lateral Movements using Domain Accounts, like Domain Admins, for example.

Also, but this is for another day :P, local Administrator account should have different password between computers. For that, implements **LAPS** (Local Administrator Password Solution).

# Script

The script has two working modes: Using an Organizational Unit or without using an OU.

## With OU

With OU, the script will list the OUs in the domain and ask for entering the DN of the target OU the GPO will be linked to. Also, the script will ask for moving automatically all the computers indicated in a file by Computer Name (line by line) to the target OU.

 ![Example Execution Linking to OU](assets/ou.gif?token=GHSAT0AAAAAABT6ZRI2GVYF66OFNJV4BYGOYVUYF3Q)

![Example Created GPO](assets/ou.png?token=GHSAT0AAAAAABT6ZRI2BTJ65RUDLKKH2B2GYVUYF6A)

## Without OU

Without OU the GPO will be linked to domain. The script has three options.
1. Add all the computers to the security filter.
    1.1 Only the computers indicated in a file by Computer Name (line by line) will be added to the security filter (Read and Apply permissions).
2 Create a group, add compputers to the group and then add that group to the security filter.
    2.1 Only a newly created Security Group will be added to the security filter (Read and Apply permissions) with the computers indicated in a file by Computer Name (line by line) added to a newly created group.
3. Link To Domain
    3.1. You may want to use a WMI filter in this case. https://github.com/darkoperator/powershell_scripts/blob/master/install-wmifilters.ps1

# Considerations

The GPO link will not be enabled any case

The GPO is hardcoded for thinness and written to the appropriate SYSVOL path, so only the script is neccesary. Not a recommended thing but hacky :P. This has a problem, some attributte is needed in the policy object in the Directory under cn=policies,cn=system,DC=contoso,DC=local, **gPCMachineExtensionNames** after creation with New-GPO and writting the .inf file with the config in the appropriate directory. Without it the policies defined will not show and not be applied. Also, the versionNumber attribute should be set to non-zero (tested setting it to 2, not sure if it works using 1).

```
Dn: CN={FB523DD2-BFF2-4CAB-A0DE-0F279BC12343},CN=Policies,CN=System,DC=contoso,DC=local
cn: {FB523DD2-BFF2-4CAB-A0DE-0F279BC12343}; 
displayName: Test; 
distinguishedName: CN={FB523DD2-BFF2-4CAB-A0DE-0F279BC12343},CN=Policies,CN=System,DC=contoso,DC=local; 
dSCorePropagationData (3): 6/23/2022 9:34:18 AM Pacific Daylight Time; 6/23/2022 9:34:01 AM Pacific Daylight Time; 0x0 = (  ), 0x0 = (  ); 
flags: 0; 
gPCFileSysPath: \\contoso.local\SysVol\contoso.local\Policies\{FB523DD2-BFF2-4CAB-A0DE-0F279BC12343}; 
gPCFunctionalityVersion: 2; 
gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}];
instanceType: 0x4 = ( WRITE ); 
name: {FB523DD2-BFF2-4CAB-A0DE-0F279BC12343}; 
objectCategory: CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=contoso,DC=local; 
objectClass (3): top; container; groupPolicyContainer; 
objectGUID: 2f115cec-c67c-4130-aba5-8145a786fed3; 
showInAdvancedViewOnly: TRUE; 
uSNChanged: 41048; 
uSNCreated: 41035; 
versionNumber: 2; 
whenChanged: 6/23/2022 9:37:33 AM Pacific Daylight Time; 
whenCreated: 6/23/2022 9:33:57 AM Pacific Daylight Time; 

```

The script automates this process too.

The correct way would be to use Import-GPO

Tested on Windows Server 2019.
