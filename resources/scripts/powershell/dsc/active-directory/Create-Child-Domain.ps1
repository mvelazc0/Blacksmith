# Author: Mauricio Velazco @mvelazco
# License: GPLv3
# Purpose: Create a child domain in an existing Active Directory forest
# References:
# - https://docs.microsoft.com/en-us/powershell/module/addsdeployment/install-addsdomaincontroller
# - Based on Create-AD.ps1 by Roberto Rodriguez @Cyb3rWard0g

configuration CreateChildDomain {
    param
    (
        [Parameter(Mandatory)]
        [String]$ChildDomainName,

        [Parameter(Mandatory)]
        [String]$ParentDomainFQDN,

        [Parameter(Mandatory)]
        [String]$ParentDomainNetbiosName,

        [Parameter(Mandatory=$false)]
        [String]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$ParentDCIPAddress,

        [Parameter(Mandatory)]
        [Object]$DomainUsers,

        [Parameter(Mandatory=$false)]
        [Object]$DomainGroups
    )
    
    Import-DscResource -ModuleName ActiveDirectoryDsc, NetworkingDsc, xPSDesiredStateConfiguration, xDnsServer, ComputerManagementDsc
    
    # Build full child domain FQDN
    $ChildDomainFQDN = "$ChildDomainName.$ParentDomainFQDN"
    
    if (!($DomainNetbiosName)) {
        [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $ChildDomainFQDN)
    }

    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    $ComputerName = Get-Content env:computername

    # Build DC path for child domain
    $DomainNameArray = $ChildDomainFQDN.split('.')
    $DCPathString = "DC=" + $DomainNameArray[0]
    $DomainNameArray | Select-Object -Skip 1 | ForEach-Object {$DCPathString = $DCPathString + ',DC=' + $_}
    
    # Parent domain credentials
    [System.Management.Automation.PSCredential]$ParentDomainCreds = New-Object System.Management.Automation.PSCredential ("$ParentDomainNetbiosName\$($AdminCreds.UserName)", $AdminCreds.Password)

    Node localhost
    {
        LocalConfigurationManager
        {           
            ConfigurationMode   = 'ApplyOnly'
            RebootNodeIfNeeded  = $true
        }

        # ***** Add DNS and AD Features *****
        WindowsFeature DNS 
        { 
            Ensure  = "Present" 
            Name    = "DNS"		
        }

        Script EnableDNSDiags
        {
            SetScript = { 
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics" 
            }
            GetScript   = { @{} }
            TestScript  = { $false }
            DependsOn   = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools
        {
            Ensure      = "Present"
            Name        = "RSAT-DNS-Server"
            DependsOn   = "[WindowsFeature]DNS"
        }

        # Set DNS to parent DC first
        DnsServerAddress SetDNS 
        { 
            Address         = $ParentDCIPAddress
            InterfaceAlias  = $InterfaceAlias
            AddressFamily   = 'IPv4'
            DependsOn       = "[WindowsFeature]DNS"
        }

        WindowsFeature ADDSInstall 
        { 
            Ensure      = "Present" 
            Name        = "AD-Domain-Services"
            DependsOn   = "[WindowsFeature]DNS" 
        } 

        WindowsFeature ADDSTools
        {
            Ensure      = "Present"
            Name        = "RSAT-ADDS-Tools"
            DependsOn   = "[WindowsFeature]ADDSInstall"
        }

        WindowsFeature ADAdminCenter
        {
            Ensure      = "Present"
            Name        = "RSAT-AD-AdminCenter"
            DependsOn   = "[WindowsFeature]ADDSInstall"
        }
        
        # ***** Wait for Parent Domain *****
        WaitForADDomain WaitForParentDomain
        {
            DomainName              = $ParentDomainFQDN
            WaitTimeout             = 600
            RestartCount            = 3
            Credential              = $ParentDomainCreds
            DependsOn               = "[DnsServerAddress]SetDNS"
        }
         
        # ***** Create Child Domain *****
        # Note: Using ParentDomainCreds (Enterprise Admin from parent) for child domain creation
        ADDomain CreateChildDomain
        {
            DomainName                      = $ChildDomainName
            DomainNetBiosName               = $DomainNetbiosName
            ParentDomainName                = $ParentDomainFQDN
            Credential                      = $AdminCreds
            DnsDelegationCredential         = $ParentDomainCreds
            SafemodeAdministratorPassword   = $AdminCreds
            DatabasePath                    = "C:\NTDS"
            LogPath                         = "C:\NTDS"
            SysvolPath                      = "C:\SYSVOL"
            DependsOn                       = "[WaitForADDomain]WaitForParentDomain", "[WindowsFeature]ADDSInstall"
        }

        PendingReboot RebootOnSignalFromCreateChildDomain
        {
            Name        = 'RebootOnSignalFromCreateChildDomain'
            DependsOn   = "[ADDomain]CreateChildDomain"
        }

        WaitForADDomain WaitForChildDCReady
        {
            DomainName              = $ChildDomainFQDN
            WaitTimeout             = 300
            RestartCount            = 3
            Credential              = $ParentDomainCreds
            WaitForValidCredentials = $true
            DependsOn               = "[PendingReboot]RebootOnSignalFromCreateChildDomain"
        }

        # ***** Create OUs *****
        # Note: DNS will be updated to include this DC via VNet DNS deployment
        xScript CreateOUs
        {
            SetScript = {
                # Verifying ADWS service is running
                $ServiceName = 'ADWS'
                $arrService = Get-Service -Name $ServiceName

                while ($arrService.Status -ne 'Running')
                {
                    Start-Service $ServiceName
                    Start-Sleep -seconds 5
                    $arrService.Refresh()
                }

                $ParentPath = $using:DCPathString
                $OUS = @(("Workstations","Workstations in the domain"),("Servers","Servers in the domain"),("LogCollectors","Servers collecting event logs"),("DomainUsers","Users in the domain"))

                foreach($OU in $OUS)
                {
                    #Check if exists, if it does skip
                    [string] $Path = "OU=$($OU[0]),$ParentPath"
                    if(![adsi]::Exists("LDAP://$Path"))
                    {
                        New-ADOrganizationalUnit -Name $OU[0] -Path $ParentPath `
                            -Description $OU[1] `
                            -ProtectedFromAccidentalDeletion $false -PassThru
                    }
                }
            }
            GetScript =  
            {
                return @{ "Result" = "false" }
            }
            TestScript = 
            {
                return $false
            }
            DependsOn = "[WaitForADDomain]WaitForChildDCReady"
        }

        # ***** Create Domain Users *****
        xScript CreateDomainUsers
        {
            SetScript = {
                # Verifying ADWS service is running
                $ServiceName = 'ADWS'
                $arrService = Get-Service -Name $ServiceName

                while ($arrService.Status -ne 'Running')
                {
                    Start-Service $ServiceName
                    Start-Sleep -seconds 5
                    $arrService.Refresh()
                }

                $DomainName = $using:ChildDomainFQDN
                $ADServer = $using:ComputerName+"."+$DomainName

                $NewDomainUsers = $using:DomainUsers
                
                foreach ($DomainUser in $NewDomainUsers)
                {
                    $UserPrincipalName = $DomainUser.SamAccountName + "@" + $DomainName
                    $DisplayName = $DomainUser.FirstName + " " + $DomainUser.LastName
                    $OUPath = "OU="+$DomainUser.UserContainer+","+$using:DCPathString
                    $SamAccountName = $DomainUser.SamAccountName
                    $ServiceName = $DomainUser.FirstName

                    $UserExists = Get-ADUser -LDAPFilter "(sAMAccountName=$SamAccountName)" -Server $ADServer -ErrorAction SilentlyContinue

                    if ($UserExists -eq $Null)
                    {
                        write-host "Creating user $UserPrincipalName .."
                        New-ADUser -Name $DisplayName `
                        -DisplayName $DisplayName `
                        -GivenName $DomainUser.FirstName `
                        -Surname $DomainUser.LastName `
                        -Department $DomainUser.Department `
                        -Title $DomainUser.JobTitle `
                        -UserPrincipalName $UserPrincipalName `
                        -SamAccountName $DomainUser.SamAccountName `
                        -Path $OUPath `
                        -AccountPassword (ConvertTo-SecureString $DomainUser.Password -AsPlainText -force) `
                        -Enabled $true `
                        -PasswordNeverExpires $true `
                        -Server $ADServer

                        if($DomainUser.Identity -Like "Domain Admins")
                        {
                            $DomainAdminUser = $DomainUser.SamAccountName
                            $Groups = @('domain admins','schema admins','enterprise admins')
                            $Groups | ForEach-Object{
                                $members = Get-ADGroupMember -Identity $_ -Recursive -Server $ADServer | Select-Object -ExpandProperty Name
                                if ($members -contains $DomainAdminUser)
                                {
                                    Write-Host "$DomainAdminUser exists in $_ "
                                }
                                else {
                                    Add-ADGroupMember -Identity $_ -Members $DomainAdminUser -Server $ADServer
                                }
                            }
                        }
                        if($DomainUser.JobTitle -Like "Service Account")
                        {
                            setspn -a $ServiceName/$DomainName $DomainName\$SamAccountName
                        }
                    }
                }
            }
            GetScript =  
            {
                return @{ "Result" = "false" }
            }
            TestScript = 
            {
                return $false
            }
            DependsOn = "[xScript]CreateOUs"
        }

        # ***** Create Domain Groups *****
        xScript CreateDomainGroups
        {
            SetScript = {
                # Verifying ADWS service is running
                $ServiceName = 'ADWS'
                $arrService = Get-Service -Name $ServiceName

                while ($arrService.Status -ne 'Running')
                {
                    Start-Service $ServiceName
                    Start-Sleep -seconds 5
                    $arrService.Refresh()
                }

                $DomainName = $using:ChildDomainFQDN
                $ADServer = $using:ComputerName+"."+$DomainName
                
                # Check if DomainGroups parameter was provided
                $NewDomainGroups = $null
                try {
                    $NewDomainGroups = $using:DomainGroups
                } catch {
                    write-host "No domain groups defined, skipping group creation"
                }
                
                if ($NewDomainGroups -and $NewDomainGroups.Count -gt 0)
                {
                    foreach ($DomainGroup in $NewDomainGroups)
                    {
                        $GroupName = $DomainGroup.Name
                        $GroupScope = $DomainGroup.Scope
                        $GroupDescription = $DomainGroup.Description
                        $GroupMembers = $DomainGroup.Members
                        
                        # Check if group exists
                        $GroupExists = Get-ADGroup -LDAPFilter "(sAMAccountName=$GroupName)" -Server $ADServer -ErrorAction SilentlyContinue
                        
                        if ($GroupExists -eq $Null)
                        {
                            write-host "Creating group $GroupName ..."
                            New-ADGroup -Name $GroupName `
                                -SamAccountName $GroupName `
                                -GroupScope $GroupScope `
                                -Description $GroupDescription `
                                -Path $using:DCPathString `
                                -Server $ADServer
                        }
                        else
                        {
                            write-host "Group $GroupName already exists"
                        }
                        
                        # Add members to group
                        if ($GroupMembers -and $GroupMembers.Count -gt 0)
                        {
                            foreach ($Member in $GroupMembers)
                            {
                                # Check if user exists before adding
                                $UserExists = Get-ADUser -LDAPFilter "(sAMAccountName=$Member)" -Server $ADServer -ErrorAction SilentlyContinue
                                if ($UserExists)
                                {
                                    # Check if already a member
                                    $IsMember = Get-ADGroupMember -Identity $GroupName -Server $ADServer | Where-Object {$_.SamAccountName -eq $Member}
                                    if (-not $IsMember)
                                    {
                                        write-host "Adding $Member to $GroupName ..."
                                        Add-ADGroupMember -Identity $GroupName -Members $Member -Server $ADServer
                                    }
                                    else
                                    {
                                        write-host "$Member is already a member of $GroupName"
                                    }
                                }
                                else
                                {
                                    write-host "Warning: User $Member does not exist, skipping..."
                                }
                            }
                        }
                    }
                }
            }
            GetScript =
            {
                return @{ "Result" = "false" }
            }
            TestScript =
            {
                return $false
            }
            DependsOn = "[xScript]CreateDomainUsers"
        }
    }
}

function Get-NetBIOSName {
    [OutputType([string])]
    param(
        [string]$DomainFQDN
    )

    if ($DomainFQDN.Contains('.')) {
        $length = $DomainFQDN.IndexOf('.')
        if ( $length -ge 16) {
            $length = 15
        }
        return $DomainFQDN.Substring(0, $length)
    }
    else {
        if ($DomainFQDN.Length -gt 15) {
            return $DomainFQDN.Substring(0, 15)
        }
        else {
            return $DomainFQDN
        }
    }
}