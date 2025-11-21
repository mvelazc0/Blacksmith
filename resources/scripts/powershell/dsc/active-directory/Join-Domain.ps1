# Author: Roberto Rodriguez @Cyb3rWard0g
# License: GPLv3
configuration Join-Domain {
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainFQDN,

        [Parameter(Mandatory=$false)]
        [String]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$DCIPAddress,

        [Parameter(Mandatory)]
        [String]$JoinOU,

        [Parameter(Mandatory=$false)]
        [String[]]$LocalAdminGroups
    )
    
    Import-DscResource -ModuleName NetworkingDsc, ActiveDirectoryDsc, xPSDesiredStateConfiguration, ComputerManagementDsc

    if (!($DomainNetbiosName)) {
        [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $DomainFQDN)
    }
    
    [System.Management.Automation.PSCredential]$DomainAdminCreds = New-Object System.Management.Automation.PSCredential ("$DomainNetbiosName\$($Admincreds.UserName)", $Admincreds.Password)

    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)
    $ComputerName = Get-Content env:computername

    Node localhost
    {
        LocalConfigurationManager
        {           
            ConfigurationMode   = 'ApplyOnly'
            RebootNodeIfNeeded  = $true
        }

        DnsServerAddress SetDNS 
        { 
            Address         = $DCIPAddress
            InterfaceAlias  = $InterfaceAlias
            AddressFamily   = 'IPv4'
        }

        # ***** Join Domain *****
        WaitForADDomain WaitForDCReady
        {
            DomainName              = $DomainFQDN
            WaitTimeout             = 300
            RestartCount            = 3
            Credential              = $DomainAdminCreds
            DependsOn               = "[DnsServerAddress]SetDNS"
        }

        Computer JoinDomain
        {
            Name          = $ComputerName 
            DomainName    = $DomainFQDN
            Credential    = $DomainAdminCreds
            JoinOU        = $JoinOU
            DependsOn  = "[WaitForADDomain]WaitForDCReady"
        }

        PendingReboot RebootAfterJoiningDomain
        {
            Name = "RebootServer"
            DependsOn = "[Computer]JoinDomain"
        }

        # ***** Add AD Groups to Local Administrators *****
        xScript AddGroupsToLocalAdmins
        {
            SetScript = {
                $DomainNetbios = $using:DomainNetbiosName
                $GroupsToAdd = $using:LocalAdminGroups
                
                if ($GroupsToAdd -and $GroupsToAdd.Count -gt 0)
                {
                    foreach ($GroupName in $GroupsToAdd)
                    {
                        $DomainGroup = "$DomainNetbios\$GroupName"
                        
                        try {
                            # Check if group is already a member
                            $LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                            $IsMember = $LocalAdmins | Where-Object {$_.Name -eq $DomainGroup}
                            
                            if (-not $IsMember)
                            {
                                write-host "Adding $DomainGroup to local Administrators..."
                                Add-LocalGroupMember -Group "Administrators" -Member $DomainGroup -ErrorAction Stop
                                write-host "Successfully added $DomainGroup to local Administrators"
                            }
                            else
                            {
                                write-host "$DomainGroup is already a member of local Administrators"
                            }
                        }
                        catch {
                            write-host "Error adding $DomainGroup to local Administrators: $_"
                        }
                    }
                }
            }
            GetScript = {
                return @{ "Result" = "false" }
            }
            TestScript = {
                return $false
            }
            DependsOn = "[PendingReboot]RebootAfterJoiningDomain"
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