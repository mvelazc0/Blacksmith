# Author: Mauricio Velazco @mvelazco
# License: GPLv3
# Purpose: Create trust relationship between two Active Directory domains/forests
# References:
# - https://docs.microsoft.com/en-us/powershell/module/activedirectory/add-addomaintrust

configuration CreateDomainTrust {
    param
    (
        [Parameter(Mandatory)]
        [String]$SourceDomainFQDN,

        [Parameter(Mandatory)]
        [String]$TargetDomainFQDN,

        [Parameter(Mandatory)]
        [String]$TargetDCIPAddress,

        [Parameter(Mandatory)]
        [ValidateSet('Forest','External','Shortcut')]
        [String]$TrustType,

        [Parameter(Mandatory)]
        [ValidateSet('Bidirectional','Inbound','Outbound')]
        [String]$TrustDirection,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$TrustPassword,

        [Parameter(Mandatory=$false)]
        [Boolean]$SelectiveAuth = $false
    )
    
    Import-DscResource -ModuleName ActiveDirectoryDsc, NetworkingDsc, xPSDesiredStateConfiguration, xDnsServer
    
    [String] $SourceDomainNetbiosName = (Get-NetBIOSName -DomainFQDN $SourceDomainFQDN)
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("$SourceDomainNetbiosName\$($AdminCreds.UserName)", $AdminCreds.Password)

    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    Node localhost
    {
        LocalConfigurationManager
        {           
            ConfigurationMode   = 'ApplyOnly'
            RebootNodeIfNeeded  = $false
        }

        # ***** Add DNS Conditional Forwarder for Target Domain *****
        xScript AddConditionalForwarder
        {
            SetScript = {
                $TargetDomain = $using:TargetDomainFQDN
                $TargetDCIP = $using:TargetDCIPAddress
                
                # Check if conditional forwarder already exists
                $Forwarder = Get-DnsServerZone -Name $TargetDomain -ErrorAction SilentlyContinue
                
                if (-not $Forwarder)
                {
                    write-host "Adding conditional forwarder for $TargetDomain to $TargetDCIP"
                    Add-DnsServerConditionalForwarderZone -Name $TargetDomain -MasterServers $TargetDCIP -ReplicationScope "Forest"
                    write-host "Conditional forwarder added successfully"
                }
                else
                {
                    write-host "Conditional forwarder for $TargetDomain already exists"
                }
            }
            GetScript = {
                return @{ "Result" = "false" }
            }
            TestScript = {
                return $false
            }
        }

        # ***** Create Trust Relationship *****
        xScript CreateTrust
        {
            SetScript = {
                $SourceDomain = $using:SourceDomainFQDN
                $TargetDomain = $using:TargetDomainFQDN
                $TrustType = $using:TrustType
                $TrustDirection = $using:TrustDirection
                $TrustPwd = $using:TrustPassword
                $SelectiveAuth = $using:SelectiveAuth
                
                # Map trust type to AD trust type
                $ADTrustType = switch ($TrustType) {
                    'Forest' { 'Forest' }
                    'External' { 'External' }
                    'Shortcut' { 'Shortcut' }
                }
                
                # Map trust direction
                $ADTrustDirection = switch ($TrustDirection) {
                    'Bidirectional' { 'Bidirectional' }
                    'Inbound' { 'Inbound' }
                    'Outbound' { 'Outbound' }
                }
                
                try {
                    # Check if trust already exists
                    $ExistingTrust = Get-ADTrust -Filter "Target -eq '$TargetDomain'" -ErrorAction SilentlyContinue
                    
                    if (-not $ExistingTrust)
                    {
                        write-host "Creating $ADTrustType trust from $SourceDomain to $TargetDomain ($ADTrustDirection)"
                        
                        # Create the trust
                        Add-ADDomainTrust `
                            -SourceDomainName $SourceDomain `
                            -TargetDomainName $TargetDomain `
                            -TrustType $ADTrustType `
                            -TrustDirection $ADTrustDirection `
                            -TrustPassword $TrustPwd.Password `
                            -Confirm:$false
                        
                        write-host "Trust created successfully"
                        
                        # Configure selective authentication if requested
                        if ($SelectiveAuth)
                        {
                            write-host "Enabling selective authentication..."
                            Set-ADTrust -Identity $TargetDomain -SelectiveAuthentication $true
                        }
                        
                        # Verify trust
                        write-host "Verifying trust..."
                        Test-ADTrust -Identity $TargetDomain
                        write-host "Trust verification complete"
                    }
                    else
                    {
                        write-host "Trust to $TargetDomain already exists"
                        
                        # Verify existing trust
                        write-host "Verifying existing trust..."
                        Test-ADTrust -Identity $TargetDomain
                    }
                }
                catch {
                    write-host "Error creating trust: $_"
                    throw
                }
            }
            GetScript = {
                return @{ "Result" = "false" }
            }
            TestScript = {
                return $false
            }
            DependsOn = "[xScript]AddConditionalForwarder"
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