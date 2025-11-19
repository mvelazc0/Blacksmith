"""
Template Builder Module

Builds ARM templates from configuration and component modules.
"""

from typing import Dict, Any, List
from pathlib import Path
import json
import sys


class TemplateBuilder:
    """Build ARM templates from configuration."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the TemplateBuilder.
        
        Args:
            config: Parsed configuration dictionary
        """
        self.config = config
        self.template: Dict[str, Any] = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {},
            "variables": {},
            "resources": [],
            "outputs": {}
        }
        self.base_dir = Path(__file__).parent.parent.parent
    
    def build(self) -> Dict[str, Any]:
        """
        Build the complete ARM template.
        
        Returns:
            Complete ARM template dictionary
        """
        # Add parameters
        self._add_parameters()
        
        # Add variables
        self._add_variables()
        
        # Add network resources
        self._add_network_resources()
        
        # Add compute resources
        self._add_compute_resources()
        
        # Add service configurations
        self._add_service_resources()
        
        # Add logging resources (if enabled)
        self._add_logging_resources()
        
        # Add outputs
        self._add_outputs()
        
        return self.template
    
    def _add_parameters(self):
        """Add parameters to the template."""
        creds = self.config.get('credentials', {})
        
        self.template["parameters"] = {
            "adminUsername": {
                "type": "string",
                "metadata": {
                    "description": "Admin username for all VMs"
                }
            },
            "adminPassword": {
                "type": "securestring",
                "minLength": 12,
                "metadata": {
                    "description": "Admin password for all VMs"
                }
            },
            "location": {
                "type": "string",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {
                    "description": "Location for all resources"
                }
            },
            "utcValue": {
                "type": "string",
                "defaultValue": "[utcNow()]",
                "metadata": {
                    "description": "UTC timestamp for unique naming"
                }
            }
        }
        
        # Add domain-specific parameters if AD is enabled
        ad_config = self.config.get('active_directory', {})
        if ad_config.get('enabled'):
            self.template["parameters"]["domainFQDN"] = {
                "type": "string",
                "defaultValue": ad_config.get('domain_fqdn', 'blacksmith.local'),
                "metadata": {
                    "description": "Active Directory domain FQDN"
                }
            }
            self.template["parameters"]["domainNetbiosName"] = {
                "type": "string",
                "defaultValue": ad_config.get('domain_netbios', 'BLACKSMITH'),
                "metadata": {
                    "description": "Active Directory NetBIOS name"
                }
            }
    
    def _add_variables(self):
        """Add variables to the template."""
        network = self.config.get('network', {})
        
        self.template["variables"] = {
            "storageAccountName": "[concat(uniquestring(resourceGroup().id, deployment().name, parameters('utcValue')))]",
            "virtualNetworkName": network.get('vnet_name', 'vnet-lab'),
            "virtualNetworkAddressRange": network.get('address_space', '192.168.0.0/16'),
            "location": "[parameters('location')]"
        }
        
        # Add subnet variables
        subnets = network.get('subnets', [])
        if subnets:
            self.template["variables"]["subnets"] = [
                {
                    "name": subnet.get('name'),
                    "properties": {
                        "addressPrefix": subnet.get('address_prefix')
                    }
                }
                for subnet in subnets
            ]
    
    def _add_network_resources(self):
        """Add network resources to the template."""
        network = self.config.get('network', {})
        remote_access = network.get('remote_access', {})
        resources = []
        
        # Prepare subnets list (including Bastion subnet if needed)
        subnets_to_create = list(network.get('subnets', []))
        
        # Add Azure Bastion subnet if mode is AzureBastionHost
        if remote_access.get('mode') == 'AzureBastionHost':
            bastion_config = remote_access.get('bastion', {})
            if bastion_config.get('enabled', True):
                bastion_subnet = {
                    'name': 'AzureBastionSubnet',
                    'address_prefix': bastion_config.get('subnet_prefix', '192.168.3.0/26')
                }
                subnets_to_create.append(bastion_subnet)
        
        # Virtual Network with subnets defined inline (avoids AnotherOperationInProgress errors)
        vnet_resource = {
            "type": "Microsoft.Network/virtualNetworks",
            "apiVersion": "2021-05-01",
            "name": "[variables('virtualNetworkName')]",
            "location": "[parameters('location')]",
            "properties": {
                "addressSpace": {
                    "addressPrefixes": [
                        "[variables('virtualNetworkAddressRange')]"
                    ]
                },
                "subnets": [
                    {
                        "name": subnet.get('name'),
                        "properties": {
                            "addressPrefix": subnet.get('address_prefix')
                        }
                    }
                    for subnet in subnets_to_create
                ]
            }
        }
        resources.append(vnet_resource)
        
        # Network Security Group
        nsg_config = network.get('nsg', {})
        if nsg_config:
            nsg_resource = {
                "type": "Microsoft.Network/networkSecurityGroups",
                "apiVersion": "2021-05-01",
                "name": nsg_config.get('name', 'nsg-default'),
                "location": "[parameters('location')]",
                "properties": {
                    "securityRules": [
                        {
                            "name": rule.get('name'),
                            "properties": {
                                "priority": rule.get('priority'),
                                "direction": rule.get('direction'),
                                "access": rule.get('access'),
                                "protocol": rule.get('protocol'),
                                "sourcePortRange": rule.get('source_port', '*'),
                                "destinationPortRange": rule.get('destination_port'),
                                "sourceAddressPrefix": rule.get('source_address', '*'),
                                "destinationAddressPrefix": "*"
                            }
                        }
                        for rule in nsg_config.get('rules', [])
                    ]
                }
            }
            resources.append(nsg_resource)
        
        # Storage Account
        storage_resource = {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2021-04-01",
            "name": "[variables('storageAccountName')]",
            "location": "[parameters('location')]",
            "sku": {
                "name": "Standard_LRS"
            },
            "kind": "Storage",
            "properties": {
                "allowBlobPublicAccess": False
            }
        }
        resources.append(storage_resource)
        
        # Azure Bastion Host
        if remote_access.get('mode') == 'AzureBastionHost':
            bastion_resources = self._create_bastion_resources(network)
            resources.extend(bastion_resources)
        
        self.template["resources"].extend(resources)
    
    def _generate_vm_name(self, vm: Dict[str, Any], index: int) -> str:
        """
        Generate VM name based on configuration.
        
        Args:
            vm: VM configuration dictionary
            index: Instance index (0-based)
            
        Returns:
            Generated VM name
        """
        base_name = vm.get('name', '')
        suffix = vm.get('suffix', '')
        naming_pattern = vm.get('naming_pattern', 'suffix-number')
        count = vm.get('count', 1)
        
        # Determine the prefix to use
        # Priority: suffix > name > default
        if suffix:
            prefix = suffix
        elif base_name:
            prefix = base_name
        else:
            prefix = 'VM'  # Fallback default
        
        # If count is 1 and we have a name (not suffix), just use the name as-is
        if count == 1 and base_name and not suffix:
            return base_name
        
        # Generate number with zero-padding (01, 02, etc.)
        # Determine padding based on count
        if count < 10:
            number = f"{(index + 1):02d}"  # Always use 2 digits for consistency (01-09)
        elif count < 100:
            number = f"{(index + 1):02d}"
        else:
            number = f"{(index + 1):03d}"
        
        # Apply naming pattern
        if naming_pattern == 'suffix-number':
            # e.g., srv01, srv02
            return f"{prefix}{number}"
        elif naming_pattern == 'number-suffix':
            # e.g., 01srv, 02srv
            return f"{number}{prefix}"
        elif naming_pattern == 'suffix-only':
            # e.g., srv1, srv2 (no zero padding)
            return f"{prefix}{(index + 1)}"
        else:
            # Default to suffix-number
            return f"{prefix}{number}"
    
    def _add_compute_resources(self):
        """Add compute resources (VMs) to the template."""
        vms = self.config.get('virtual_machines', [])
        network = self.config.get('network', {})
        remote_access = network.get('remote_access', {})
        
        # Only create DC and servers directly - workstations will be created via nested deployment
        for vm in vms:
            # Skip workstations - they'll be handled by Win10 nested deployment
            if vm.get('role') != 'domain_controller' and vm.get('type') == 'windows_desktop':
                continue
                
            count = vm.get('count', 1)
            
            # For VMs with count > 1, create multiple instances
            for i in range(count):
                instance_name = self._generate_vm_name(vm, i)
                
                # Public IP (if needed)
                if remote_access.get('mode') == 'AllowPublicIP':
                    pip_resource = {
                        "type": "Microsoft.Network/publicIPAddresses",
                        "apiVersion": "2021-05-01",
                        "name": f"pip-{instance_name}",
                        "location": "[parameters('location')]",
                        "properties": {
                            "publicIPAllocationMethod": "Dynamic"
                        }
                    }
                    self.template["resources"].append(pip_resource)
                
                # Network Interface
                nic_resource = self._create_nic_resource(vm, instance_name, i)
                self.template["resources"].append(nic_resource)
                
                # Virtual Machine
                vm_resource = self._create_vm_resource(vm, instance_name)
                self.template["resources"].append(vm_resource)
        
        # Add workstations via nested deployment
        self._add_workstations_deployment()
    
    def _calculate_vm_ip(self, vm: Dict[str, Any], index: int) -> str:
        """
        Calculate IP address for VM instance.
        
        Args:
            vm: VM configuration dictionary
            index: Instance index (0-based)
            
        Returns:
            IP address string
        """
        vm_network = vm.get('network', {})
        count = vm.get('count', 1)
        
        # Check if ip_start is provided - if so, use it for IP calculation
        ip_start = vm_network.get('ip_start')
        if ip_start:
            # Use ip_start and increment by index
            ip_parts = ip_start.split('.')
            ip_parts[-1] = str(int(ip_parts[-1]) + index)
            return '.'.join(ip_parts)
        
        # Otherwise use private_ip (for single VMs with explicit IP)
        private_ip = vm_network.get('private_ip')
        if private_ip:
            if count > 1:
                # Multiple VMs but only private_ip given - increment from it
                ip_parts = private_ip.split('.')
                ip_parts[-1] = str(int(ip_parts[-1]) + index)
                return '.'.join(ip_parts)
            else:
                # Single VM with explicit private_ip
                return private_ip
        
        # Fallback default (should rarely be used)
        return f"192.168.1.{10 + index}"
    
    def _create_nic_resource(self, vm: Dict[str, Any], instance_name: str, index: int) -> Dict[str, Any]:
        """Create network interface resource."""
        network = self.config.get('network', {})
        vm_network = vm.get('network', {})
        subnet_name = vm_network.get('subnet', 'default')
        
        # Calculate IP address using helper method
        private_ip = self._calculate_vm_ip(vm, index)
        
        nic = {
            "type": "Microsoft.Network/networkInterfaces",
            "apiVersion": "2021-05-01",
            "name": f"nic-{instance_name}",
            "location": "[parameters('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
            ],
            "properties": {
                "ipConfigurations": [
                    {
                        "name": "ipconfig1",
                        "properties": {
                            "privateIPAllocationMethod": "Static",
                            "privateIPAddress": private_ip,
                            "subnet": {
                                "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('virtualNetworkName'), '" + subnet_name + "')]"
                            }
                        }
                    }
                ]
            }
        }
        
        # Add public IP if needed
        remote_access = network.get('remote_access', {})
        if remote_access.get('mode') == 'AllowPublicIP':
            nic["dependsOn"].append(f"[resourceId('Microsoft.Network/publicIPAddresses', 'pip-{instance_name}')]")
            nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"] = {
                "id": f"[resourceId('Microsoft.Network/publicIPAddresses', 'pip-{instance_name}')]"
            }
        
        return nic
    
    def _create_vm_resource(self, vm: Dict[str, Any], instance_name: str) -> Dict[str, Any]:
        """Create virtual machine resource."""
        vm_type = vm.get('type')
        os_config = vm.get('os', {})
        
        # Determine image reference based on VM type
        if vm_type == 'windows_server':
            image_ref = {
                "publisher": "MicrosoftWindowsServer",
                "offer": "WindowsServer",
                "sku": os_config.get('sku', '2019-Datacenter'),
                "version": os_config.get('version', 'latest')
            }
        elif vm_type == 'windows_desktop':
            sku = os_config.get('sku', 'win10-22h2-pro')
            offer = 'windows-11' if 'win11' in sku else 'Windows-10'
            image_ref = {
                "publisher": "MicrosoftWindowsDesktop",
                "offer": offer,
                "sku": sku,
                "version": os_config.get('version', 'latest')
            }
        else:  # linux
            image_ref = {
                "publisher": "Canonical",
                "offer": "0001-com-ubuntu-server-focal",
                "sku": os_config.get('sku', '20_04-lts'),
                "version": os_config.get('version', 'latest')
            }
        
        vm_resource = {
            "type": "Microsoft.Compute/virtualMachines",
            "apiVersion": "2021-11-01",
            "name": instance_name,
            "location": "[parameters('location')]",
            "dependsOn": [
                f"[resourceId('Microsoft.Network/networkInterfaces', 'nic-{instance_name}')]",
                "[resourceId('Microsoft.Storage/storageAccounts', variables('storageAccountName'))]"
            ],
            "properties": {
                "hardwareProfile": {
                    "vmSize": vm.get('size', 'Standard_B2ms')
                },
                "osProfile": {
                    "computerName": instance_name,
                    "adminUsername": "[parameters('adminUsername')]",
                    "adminPassword": "[parameters('adminPassword')]"
                },
                "storageProfile": {
                    "imageReference": image_ref,
                    "osDisk": {
                        "createOption": "FromImage"
                    }
                },
                "networkProfile": {
                    "networkInterfaces": [
                        {
                            "id": f"[resourceId('Microsoft.Network/networkInterfaces', 'nic-{instance_name}')]"
                        }
                    ]
                },
                "diagnosticsProfile": {
                    "bootDiagnostics": {
                        "enabled": True,
                        "storageUri": "[reference(resourceId('Microsoft.Storage/storageAccounts', variables('storageAccountName'))).primaryEndpoints.blob]"
                    }
                }
            }
        }
        
        # Add identity - default to SystemAssigned for Azure Monitor Agent support
        identity = vm.get('identity', {})
        identity_type = identity.get('type', 'SystemAssigned')
        
        if identity_type and identity_type != 'None':
            vm_resource["identity"] = {"type": identity_type}
        
        return vm_resource
    
    def _create_bastion_resources(self, network: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Create Azure Bastion Host resources.
        
        Args:
            network: Network configuration dictionary
            
        Returns:
            List of Bastion-related resources
        """
        resources = []
        remote_access = network.get('remote_access', {})
        bastion_config = remote_access.get('bastion', {})
        
        # Bastion Public IP
        bastion_pip = {
            "type": "Microsoft.Network/publicIPAddresses",
            "apiVersion": "2021-05-01",
            "name": "pip-bastion",
            "location": "[parameters('location')]",
            "sku": {
                "name": "Standard"
            },
            "properties": {
                "publicIPAllocationMethod": "Static"
            }
        }
        resources.append(bastion_pip)
        
        # Azure Bastion Host
        bastion_host = {
            "type": "Microsoft.Network/bastionHosts",
            "apiVersion": "2021-05-01",
            "name": "[concat(variables('virtualNetworkName'), '-bastion')]",
            "location": "[parameters('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/publicIPAddresses', 'pip-bastion')]",
                "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
            ],
            "properties": {
                "ipConfigurations": [
                    {
                        "name": "bastionIpConfig",
                        "properties": {
                            "subnet": {
                                "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('virtualNetworkName'), 'AzureBastionSubnet')]"
                            },
                            "publicIPAddress": {
                                "id": "[resourceId('Microsoft.Network/publicIPAddresses', 'pip-bastion')]"
                            }
                        }
                    }
                ]
            }
        }
        resources.append(bastion_host)
        
        return resources
    
    def _add_service_resources(self):
        """Add service-specific resources and extensions using existing ARM templates."""
        ad_config = self.config.get('active_directory', {})
        
        if ad_config.get('enabled'):
            # Get domain controller VM
            vms = self.config.get('virtual_machines', [])
            dc_vm = next((vm for vm in vms if vm.get('role') == 'domain_controller'), None)
            
            if dc_vm:
                dc_name = dc_vm.get('name')
                dc_ip = dc_vm.get('network', {}).get('private_ip', '192.168.1.4')
                
                # Step 1: Add prep script to install DSC modules on DC
                self._add_dc_prep_extension(dc_name)
                
                # Step 2: Create AD forest using nested deployment
                self._add_create_ad_forest_deployment(dc_name, ad_config)
                
                # Step 3: Update VNet DNS to point to DC
                self._add_update_vnet_dns_deployment(dc_ip)
                
                # Step 4: Join workstations to domain (via nested deployment)
                self._add_domain_join_deployment(dc_name, dc_ip, ad_config)
                
                # Step 5: Join servers to domain (via DSC extensions)
                self._add_server_domain_join_extensions(dc_name, dc_ip, ad_config)
    
    def _add_outputs(self):
        """Add outputs to the template."""
        self.template["outputs"] = {
            "virtualNetworkName": {
                "type": "string",
                "value": "[variables('virtualNetworkName')]"
            },
            "virtualNetworkId": {
                "type": "string",
                "value": "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
            }
        }
    
    def _add_dc_prep_extension(self, dc_name: str):
        """Add Custom Script Extension to prepare DC (install DSC modules)."""
        prep_extension = {
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "apiVersion": "2021-11-01",
            "name": f"{dc_name}/SetUpDC",
            "location": "[parameters('location')]",
            "dependsOn": [
                f"[resourceId('Microsoft.Compute/virtualMachines', '{dc_name}')]"
            ],
            "properties": {
                "publisher": "Microsoft.Compute",
                "type": "CustomScriptExtension",
                "typeHandlerVersion": "1.8",
                "autoUpgradeMinorVersion": True,
                "settings": {
                    "fileUris": [
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Set-Initial-Settings.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Install-DSC-Modules.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Prepare-Box.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Box.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Firewall.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Configure-PSRemoting.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Enable-WinAuditCategories.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Enable-PowerShell-Logging.ps1",
                        "https://raw.githubusercontent.com/OTRF/Set-AuditRule/master/Set-AuditRule.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Set-SACLs.ps1",
                        "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Set-WallPaper.ps1"
                    ],
                    "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ./Set-Initial-Settings.ps1 -SetupType DC"
                },
                "protectedSettings": {}
            }
        }
        
        self.template["resources"].append(prep_extension)
    
    def _add_workstation_prep_extensions(self):
        """Add Custom Script Extensions to prepare workstations (install DSC modules)."""
        vms = self.config.get('virtual_machines', [])
        
        for vm in vms:
            # Skip domain controller
            if vm.get('role') == 'domain_controller':
                continue
            
            count = vm.get('count', 1)
            
            # Handle multiple instances
            for i in range(count):
                instance_name = self._generate_vm_name(vm, i)
                
                # Custom Script Extension to install DSC modules
                prep_extension = {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "apiVersion": "2021-11-01",
                    "name": f"{instance_name}/SetUpWorkstation",
                    "location": "[parameters('location')]",
                    "dependsOn": [
                        f"[resourceId('Microsoft.Compute/virtualMachines', '{instance_name}')]",
                        "[resourceId('Microsoft.Resources/deployments', 'UpdateVNetDNS')]"
                    ],
                    "properties": {
                        "publisher": "Microsoft.Compute",
                        "type": "CustomScriptExtension",
                        "typeHandlerVersion": "1.8",
                        "autoUpgradeMinorVersion": True,
                        "settings": {
                            "fileUris": [
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Set-Initial-Settings.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Install-DSC-Modules.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Prepare-Box.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Box.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Firewall.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Configure-PSRemoting.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Enable-WinAuditCategories.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Enable-PowerShell-Logging.ps1",
                                "https://raw.githubusercontent.com/OTRF/Set-AuditRule/master/Set-AuditRule.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/auditing/Set-SACLs.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Set-WallPaper.ps1"
                            ],
                            "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ./Set-Initial-Settings.ps1"
                        },
                        "protectedSettings": {}
                    }
                }
                
                self.template["resources"].append(prep_extension)
    
    def _add_create_ad_forest_deployment(self, dc_name: str, ad_config: Dict[str, Any]):
        """Add nested deployment to create AD forest using existing ARM template."""
        domain_fqdn = ad_config.get('domain_fqdn', 'blacksmith.local')
        
        # Prepare domain users array
        users = ad_config.get('users', [])
        domain_users_array = []
        for user in users:
            domain_users_array.append({
                "FirstName": user.get('first_name', ''),
                "LastName": user.get('last_name', ''),
                "SamAccountName": user.get('sam_account', ''),
                "Department": user.get('department', ''),
                "JobTitle": user.get('job_title', ''),
                "Password": user.get('password', ''),
                "Identity": user.get('groups', ['Users'])[0] if user.get('groups') else 'Users',
                "UserContainer": "DomainUsers"
            })
        
        # Nested deployment that calls the existing createADForest template
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2021-04-01",
            "name": "CreateADForest",
            "dependsOn": [
                f"[resourceId('Microsoft.Compute/virtualMachines/extensions', '{dc_name}', 'SetUpDC')]"
            ],
            "properties": {
                "mode": "Incremental",
                "templateLink": {
                    "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/nestedtemplates/createADForest.json",
                    "contentVersion": "1.0.0.0"
                },
                "parameters": {
                    "vmName": {
                        "value": dc_name
                    },
                    "createADForestScript": {
                        "value": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/dsc/active-directory/Create-AD.zip"
                    },
                    "domainFQDN": {
                        "value": domain_fqdn
                    },
                    "adminUsername": {
                        "value": "[parameters('adminUsername')]"
                    },
                    "adminPassword": {
                        "value": "[parameters('adminPassword')]"
                    },
                    "domainUsers": {
                        "value": {"array": domain_users_array}
                    },
                    "location": {
                        "value": "[parameters('location')]"
                    }
                }
            }
        }
        
        self.template["resources"].append(deployment)
    
    def _add_update_vnet_dns_deployment(self, dc_ip: str):
        """Add nested deployment to update VNet DNS using existing ARM template."""
        network = self.config.get('network', {})
        subnets = network.get('subnets', [])
        remote_access = network.get('remote_access', {})
        
        # Build subnets array
        subnets_array = []
        for subnet in subnets:
            subnets_array.append({
                "name": subnet.get('name'),
                "properties": {
                    "addressPrefix": subnet.get('address_prefix')
                }
            })
        
        # Add Bastion subnet if needed
        if remote_access.get('mode') == 'AzureBastionHost':
            bastion_config = remote_access.get('bastion', {})
            if bastion_config.get('enabled', True):
                subnets_array.append({
                    "name": "AzureBastionSubnet",
                    "properties": {
                        "addressPrefix": bastion_config.get('subnet_prefix', '192.168.3.0/26')
                    }
                })
        
        # Nested deployment that calls the existing vnet-dns-server template
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2021-04-01",
            "name": "UpdateVNetDNS",
            "dependsOn": [
                "[resourceId('Microsoft.Resources/deployments', 'CreateADForest')]"
            ],
            "properties": {
                "mode": "Incremental",
                "templateLink": {
                    "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD/nestedtemplates/vnet-dns-server.json",
                    "contentVersion": "1.0.0.0"
                },
                "parameters": {
                    "virtualNetworkName": {
                        "value": "[variables('virtualNetworkName')]"
                    },
                    "virtualNetworkAddressRange": {
                        "value": "[variables('virtualNetworkAddressRange')]"
                    },
                    "subnets": {
                        "value": subnets_array
                    },
                    "DNSServerAddress": {
                        "value": [dc_ip]
                    },
                    "location": {
                        "value": "[parameters('location')]"
                    }
                }
            }
        }
        
        self.template["resources"].append(deployment)
    
    
    def _add_workstations_deployment(self):
        """Add nested deployment to create workstations using Win10 template."""
        vms = self.config.get('virtual_machines', [])
        network = self.config.get('network', {})
        remote_access = network.get('remote_access', {})
        
        # Find workstation VMs
        workstation_vms = [vm for vm in vms if vm.get('role') != 'domain_controller' and vm.get('type') == 'windows_desktop']
        
        if not workstation_vms:
            return
        
        # For now, handle single workstation config (can be extended for multiple)
        workstation = workstation_vms[0]
        count = workstation.get('count', 1)
        suffix = workstation.get('suffix', '')
        naming_pattern = workstation.get('naming_pattern', 'suffix-number')
        
        # Get IP configuration
        vm_network = workstation.get('network', {})
        subnet_name = vm_network.get('subnet', 'default')
        
        # Calculate starting IP for the first workstation
        private_ip = vm_network.get('ip_start') or vm_network.get('private_ip', '192.168.1.5')
        ip_suffix = int(private_ip.split('.')[-1])
        
        # Determine prefix and suffix for Win10 template
        # The Win10 template uses vmNamePrefix + vmNameSuffix pattern
        # IMPORTANT: vmNameSuffix is used for BOTH naming AND IP calculation in Win10 template
        # So we need to use the IP suffix, not just 1
        if suffix:
            # User provided a suffix - use it as the prefix
            vm_name_prefix = suffix
            vm_name_suffix = ip_suffix  # Use IP suffix for proper IP allocation
        else:
            # No suffix provided - use the configured name
            configured_name = workstation.get('name', 'WORKSTATION')
            # Extract any trailing number from the name
            import re
            match = re.match(r'^(.+?)(\d+)$', configured_name)
            if match:
                vm_name_prefix = match.group(1)  # e.g., "WORKSTATION"
                vm_name_suffix = int(match.group(2))  # e.g., 5
            else:
                # No number at end
                vm_name_prefix = configured_name
                vm_name_suffix = ip_suffix  # Use IP suffix
        
        # Find the subnet configuration to get address prefix
        subnets = network.get('subnets', [])
        subnet_range = '192.168.1.0/24'  # default
        for subnet in subnets:
            if subnet.get('name') == subnet_name:
                subnet_range = subnet.get('address_prefix', '192.168.1.0/24')
                break
        
        # Get OS configuration
        os_config = workstation.get('os', {})
        sku = os_config.get('sku', 'win10-22h2-pro')
        
        # Build dependencies list
        dependencies = [
            "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
        ]
        
        # Add NSG dependency if it exists
        nsg_config = network.get('nsg', {})
        if nsg_config:
            nsg_name = nsg_config.get('name', 'nsg-rdp-allow')
            dependencies.append(f"[resourceId('Microsoft.Network/networkSecurityGroups', '{nsg_name}')]")
        
        # Nested deployment that calls the Win10 template
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2021-04-01",
            "name": "deployWorkstations",
            "dependsOn": dependencies,
            "properties": {
                "mode": "Incremental",
                "templateLink": {
                    "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10/azuredeploy.json",
                    "contentVersion": "1.0.0.0"
                },
                "parameters": {
                    "adminUsername": {
                        "value": "[parameters('adminUsername')]"
                    },
                    "adminPassword": {
                        "value": "[parameters('adminPassword')]"
                    },
                    "numberOfWorkstations": {
                        "value": count
                    },
                    "vmNamePrefix": {
                        "value": vm_name_prefix
                    },
                    "vmNameSuffix": {
                        "value": vm_name_suffix
                    },
                    "windowsDesktopSKU": {
                        "value": sku
                    },
                    "windowsDesktopVersion": {
                        "value": os_config.get('version', 'latest')
                    },
                    "vmSize": {
                        "value": workstation.get('size', 'Standard_B2ms')
                    },
                    "newOrExistingVnet": {
                        "value": "existing"
                    },
                    "virtualNetworkName": {
                        "value": "[variables('virtualNetworkName')]"
                    },
                    "virtualNetworkAddressRange": {
                        "value": "[variables('virtualNetworkAddressRange')]"
                    },
                    "newOrExistingSubnet": {
                        "value": "existing"
                    },
                    "subnetName": {
                        "value": subnet_name
                    },
                    "subnetRange": {
                        "value": subnet_range
                    },
                    "newOrExistingNSG": {
                        "value": "existing" if network.get('nsg') else "new"
                    },
                    "networkSecurityGroupName": {
                        "value": network.get('nsg', {}).get('name', 'nsg-rdp-allow')
                    },
                    "remoteAccessMode": {
                        "value": remote_access.get('mode', 'AllowPublicIP')
                    },
                    "allowedIPAddresses": {
                        "value": remote_access.get('allowed_ips', '*')
                    },
                    "newOrExistingBastion": {
                        "value": "existing"
                    },
                    "identityType": {
                        "value": "SystemAssigned"
                    },
                    "enableSysmon": {
                        "value": False
                    },
                    "location": {
                        "value": "[parameters('location')]"
                    }
                }
            }
        }
        
        self.template["resources"].append(deployment)
    
    def _add_domain_join_deployment(self, dc_name: str, dc_ip: str, ad_config: Dict[str, Any]):
        """Add nested deployment to join workstations to domain using existing ARM template."""
        domain_fqdn = ad_config.get('domain_fqdn', 'blacksmith.local')
        domain_netbios = ad_config.get('domain_netbios', 'BLACKSMITH')
        
        # Build OU path
        domain_parts = domain_fqdn.split('.')
        ou_path = f"OU=Workstations;DC={';DC='.join(domain_parts)}"
        
        # Check if we have workstations to join
        vms = self.config.get('virtual_machines', [])
        has_workstations = any(vm.get('role') != 'domain_controller' and vm.get('type') == 'windows_desktop' for vm in vms)
        
        if has_workstations:
            # Nested deployment that calls the existing joinDomain template
            # Uses output from deployWorkstations nested deployment
            deployment = {
                "type": "Microsoft.Resources/deployments",
                "apiVersion": "2021-04-01",
                "name": "JoinWorkstations",
                "dependsOn": [
                    "[resourceId('Microsoft.Resources/deployments', 'deployWorkstations')]",
                    "[resourceId('Microsoft.Resources/deployments', 'UpdateVNetDNS')]"
                ],
                "properties": {
                    "mode": "Incremental",
                    "templateLink": {
                        "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD/nestedtemplates/joinDomain.json",
                        "contentVersion": "1.0.0.0"
                    },
                    "parameters": {
                        "virtualMachines": {
                            "value": "[reference('deployWorkstations').outputs.allWinVMsDeployed.value]"
                        },
                        "joinDomainScript": {
                            "value": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/dsc/active-directory/Join-Domain.zip"
                        },
                        "domainFQDN": {
                            "value": domain_fqdn
                        },
                        "domainNetbiosName": {
                            "value": domain_netbios
                        },
                        "adminUsername": {
                            "value": "[parameters('adminUsername')]"
                        },
                        "adminPassword": {
                            "value": "[parameters('adminPassword')]"
                        },
                        "dcIpAddress": {
                            "value": dc_ip
                        },
                        "joinOU": {
                            "value": ou_path
                        },
                        "location": {
                            "value": "[parameters('location')]"
                        }
                    }
                }
            }
            
            self.template["resources"].append(deployment)
    
    def _add_server_domain_join_extensions(self, dc_name: str, dc_ip: str, ad_config: Dict[str, Any]):
        """Add prep and domain join extensions for servers."""
        domain_fqdn = ad_config.get('domain_fqdn', 'blacksmith.local')
        domain_netbios = ad_config.get('domain_netbios', 'BLACKSMITH')
        
        # Build OU path for servers
        domain_parts = domain_fqdn.split('.')
        ou_path = f"OU=Servers;DC={';DC='.join(domain_parts)}"
        
        # Get all server VMs that need to join the domain (not the DC itself, not workstations)
        vms = self.config.get('virtual_machines', [])
        servers_to_join = [
            vm for vm in vms
            if vm.get('role') != 'domain_controller'
            and vm.get('type') != 'windows_desktop'
        ]
        
        for vm in servers_to_join:
            count = vm.get('count', 1)
            
            # Handle multiple instances
            for i in range(count):
                instance_name = self._generate_vm_name(vm, i)
                
                # Step 1: Add prep extension to install DSC modules (same as DC prep)
                prep_extension = {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "apiVersion": "2021-11-01",
                    "name": f"{instance_name}/SetUpServer",
                    "location": "[parameters('location')]",
                    "dependsOn": [
                        f"[resourceId('Microsoft.Compute/virtualMachines', '{instance_name}')]"
                    ],
                    "properties": {
                        "publisher": "Microsoft.Compute",
                        "type": "CustomScriptExtension",
                        "typeHandlerVersion": "1.8",
                        "autoUpgradeMinorVersion": True,
                        "settings": {
                            "fileUris": [
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Set-Initial-Settings.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Win10-AD-WEC/scripts/Install-DSC-Modules.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Prepare-Box.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Box.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Disarm-Firewall.ps1",
                                "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/misc/Configure-PSRemoting.ps1"
                            ],
                            "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File ./Install-DSC-Modules.ps1"
                        },
                        "protectedSettings": {}
                    }
                }
                self.template["resources"].append(prep_extension)
                
                # Step 2: DSC extension for domain join (depends on prep)
                join_extension = {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "apiVersion": "2021-11-01",
                    "name": f"{instance_name}/JoinDomain",
                    "location": "[parameters('location')]",
                    "dependsOn": [
                        f"[resourceId('Microsoft.Compute/virtualMachines/extensions', '{instance_name}', 'SetUpServer')]",
                        "[resourceId('Microsoft.Resources/deployments', 'UpdateVNetDNS')]"
                    ],
                    "properties": {
                        "publisher": "Microsoft.Powershell",
                        "type": "DSC",
                        "typeHandlerVersion": "2.77",
                        "autoUpgradeMinorVersion": True,
                        "settings": {
                            "wmfVersion": "latest",
                            "configuration": {
                                "url": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/dsc/active-directory/Join-Domain.zip",
                                "script": "Join-Domain.ps1",
                                "function": "Join-Domain"
                            },
                            "configurationArguments": {
                                "DomainFQDN": domain_fqdn,
                                "DomainNetbiosName": domain_netbios,
                                "DCIPAddress": dc_ip,
                                "JoinOU": ou_path
                            }
                        },
                        "protectedSettings": {
                            "configurationArguments": {
                                "AdminCreds": {
                                    "UserName": "[parameters('adminUsername')]",
                                    "Password": "[parameters('adminPassword')]"
                                }
                            }
                        }
                    }
                }
                
                self.template["resources"].append(join_extension)
    
    def _add_domain_join_extensions(self, dc_name: str, dc_ip: str, ad_config: Dict[str, Any]):
        """Add DSC extensions to join workstations to the domain."""
        domain_fqdn = ad_config.get('domain_fqdn', 'blacksmith.local')
        domain_netbios = ad_config.get('domain_netbios', 'BLACKSMITH')
        
        # Build OU path
        domain_parts = domain_fqdn.split('.')
        ou_path = f"OU=Workstations;DC={';DC='.join(domain_parts)}"
        
        # Get all VMs that need to join the domain (not the DC itself)
        vms = self.config.get('virtual_machines', [])
        vms_to_join = [vm for vm in vms if vm.get('role') != 'domain_controller']
        
        for vm in vms_to_join:
            count = vm.get('count', 1)
            
            # Handle multiple instances
            for i in range(count):
                instance_name = self._generate_vm_name(vm, i)
                
                # DSC extension for domain join
                join_extension = {
                    "type": "Microsoft.Compute/virtualMachines/extensions",
                    "apiVersion": "2021-11-01",
                    "name": f"{instance_name}/JoinDomain",
                    "location": "[parameters('location')]",
                    "dependsOn": [
                        f"[resourceId('Microsoft.Compute/virtualMachines', '{instance_name}')]",
                        "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
                    ],
                    "properties": {
                        "publisher": "Microsoft.Powershell",
                        "type": "DSC",
                        "typeHandlerVersion": "2.77",
                        "autoUpgradeMinorVersion": True,
                        "settings": {
                            "wmfVersion": "latest",
                            "configuration": {
                                "url": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/dsc/active-directory/Join-Domain.zip",
                                "script": "Join-Domain.ps1",
                                "function": "Join-Domain"
                            },
                            "configurationArguments": {
                                "DomainFQDN": domain_fqdn,
                                "DomainNetbiosName": domain_netbios,
                                "DCIPAddress": dc_ip,
                                "JoinOU": ou_path
                            }
                        },
                        "protectedSettings": {
                            "configurationArguments": {
                                "AdminCreds": {
                                    "UserName": "[parameters('adminUsername')]",
                                    "Password": "[parameters('adminPassword')]"
                                }
                            }
                        }
                    }
                }
                
                self.template["resources"].append(join_extension)
    
    def _add_logging_resources(self):
        """Add Log Analytics Workspace and Data Collection Rules if logging is enabled."""
        features = self.config.get('features', {})
        logging_config = features.get('logging', {})
        
        if not logging_config.get('enabled'):
            return
        
        # Step 1: Create Log Analytics Workspace
        workspace_resource_id = self._add_log_analytics_workspace(logging_config)
        
        # Step 2: Create Data Collection Rules
        dcr_ids = self._add_data_collection_rules(logging_config, workspace_resource_id)
        
        # Step 3: Install Azure Monitor Agents via extension
        self._add_azure_monitor_agents(logging_config, dcr_ids)
        
        # Step 4: Create DCR Associations
        self._add_dcr_associations(logging_config, dcr_ids)
    
    def _add_log_analytics_workspace(self, logging_config: Dict[str, Any]) -> str:
        """
        Create Log Analytics Workspace using nested deployment.
        Optionally enables Microsoft Sentinel if configured.
        
        Args:
            logging_config: Logging configuration dictionary
            
        Returns:
            ARM template expression for workspace resource ID
        """
        workspace_config = logging_config.get('workspace', {})
        workspace_name = workspace_config.get('name', 'blacksmith-logs')
        enable_sentinel = workspace_config.get('enable_sentinel', False)
        
        # Store workspace name for use in DCR
        self._log_workspace_name = workspace_name
        
        # Always use the regular workspace template
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2021-04-01",
            "name": "deployLogAnalyticsWorkspace",
            "properties": {
                "mode": "Incremental",
                "templateLink": {
                    "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Log-Analytics-Workspace/azuredeploy.json",
                    "contentVersion": "1.0.0.0"
                },
                "parameters": {
                    "workspaceName": {
                        "value": workspace_name
                    },
                    "pricingTier": {
                        "value": workspace_config.get('pricing_tier', 'PerGB2018')
                    },
                    "dataRetention": {
                        "value": workspace_config.get('retention_days', 30)
                    },
                    "location": {
                        "value": "[parameters('location')]"
                    }
                }
            }
        }
        
        self.template["resources"].append(deployment)
        
        # If Sentinel is enabled, add the SecurityInsights solution and onboarding state
        if enable_sentinel:
            self._add_sentinel_onboarding(workspace_name)
        
        # Return the workspace resource ID expression
        return "[reference('deployLogAnalyticsWorkspace').outputs.workspaceIdOutput.value]"
    
    def _add_sentinel_onboarding(self, workspace_name: str):
        """
        Add Microsoft Sentinel onboarding resources via nested deployment.
        
        Args:
            workspace_name: Name of the Log Analytics workspace
        """
        # Use nested deployment to enable Sentinel
        # Pass workspace name as parameter to avoid reference() issues
        sentinel_deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2021-04-01",
            "name": "deploySentinel",
            "dependsOn": [
                "[resourceId('Microsoft.Resources/deployments', 'deployLogAnalyticsWorkspace')]"
            ],
            "properties": {
                "mode": "Incremental",
                "expressionEvaluationOptions": {
                    "scope": "inner"
                },
                "parameters": {
                    "workspaceName": {
                        "value": "[reference('deployLogAnalyticsWorkspace').outputs.workspaceName_output.value]"
                    }
                },
                "template": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "workspaceName": {
                            "type": "string"
                        }
                    },
                    "variables": {},
                    "resources": [
                        {
                            "type": "Microsoft.OperationsManagement/solutions",
                            "apiVersion": "2015-11-01-preview",
                            "name": "[concat('SecurityInsights(', parameters('workspaceName'), ')')]",
                            "location": "[resourceGroup().location]",
                            "properties": {
                                "workspaceResourceId": "[concat(subscription().id, '/resourceGroups/', resourceGroup().name, '/providers/Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]"
                            },
                            "plan": {
                                "name": "[concat('SecurityInsights(', parameters('workspaceName'), ')')]",
                                "product": "OMSGallery/SecurityInsights",
                                "publisher": "Microsoft",
                                "promotionCode": ""
                            }
                        },
                        {
                            "type": "Microsoft.SecurityInsights/onboardingStates",
                            "apiVersion": "2024-03-01",
                            "name": "default",
                            "scope": "[concat('Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]",
                            "dependsOn": [
                                "[resourceId('Microsoft.OperationsManagement/solutions', concat('SecurityInsights(', parameters('workspaceName'), ')'))]"
                            ],
                            "properties": {}
                        }
                    ]
                }
            }
        }
        
        self.template["resources"].append(sentinel_deployment)
    
    def _add_data_collection_rules(self, logging_config: Dict[str, Any], workspace_resource_id: str) -> List[str]:
        """
        Create Data Collection Rules for specified data sources.
        
        Args:
            logging_config: Logging configuration dictionary
            workspace_resource_id: ARM expression for workspace resource ID
            
        Returns:
            List of DCR resource ID expressions
        """
        dcr_configs = logging_config.get('data_collection_rules', [])
        dcr_ids = []
        
        for dcr in dcr_configs:
            dcr_name = dcr.get('name', 'dcr-default')
            data_sources_config = dcr.get('data_sources', {})
            
            # Build data sources object
            data_sources = {}
            
            # Windows Event Logs - convert to ARM template format
            # Azure Monitor requires specific format for Windows Event Logs
            windows_event_logs = data_sources_config.get('windows_event_logs', [])
            if windows_event_logs:
                arm_event_logs = []
                for log_config in windows_event_logs:
                    # Each event log source needs name, streams, and xPathQueries
                    # Use Microsoft-Event for standard Event table (not Microsoft-WindowsEvent)
                    event_log_source = {
                        "name": log_config.get('name', 'eventLogsDataSource'),
                        "streams": log_config.get('streams', ['Microsoft-Event'])
                    }
                    
                    # Add xPathQueries if provided
                    xpath_queries = log_config.get('x_path_queries', [])
                    if xpath_queries:
                        event_log_source["xPathQueries"] = xpath_queries
                    
                    arm_event_logs.append(event_log_source)
                
                data_sources["windowsEventLogs"] = arm_event_logs
            
            # Performance Counters - convert to ARM template format
            performance_counters = data_sources_config.get('performance_counters', [])
            if performance_counters:
                arm_perf_counters = []
                for perf_config in performance_counters:
                    arm_perf_counters.append({
                        "name": perf_config.get('name'),
                        "streams": perf_config.get('streams', ['Microsoft-Perf']),
                        "samplingFrequencyInSeconds": perf_config.get('sampling_frequency_in_seconds', 60),
                        "counterSpecifiers": perf_config.get('counter_specifiers', [])
                    })
                data_sources["performanceCounters"] = arm_perf_counters
            
            # Build data flows
            data_flows = []
            
            # Add flow for Windows Event Logs
            if windows_event_logs:
                for log_config in windows_event_logs:
                    data_flows.append({
                        "streams": log_config.get('streams', ['Microsoft-Event']),
                        "destinations": ["centralWorkspace"],
                        "transformKql": "source",
                        "outputStream": "Microsoft-Event"
                    })
            
            # Add flow for Performance Counters
            if performance_counters:
                for perf_config in performance_counters:
                    data_flows.append({
                        "streams": perf_config.get('streams', ['Microsoft-Perf']),
                        "destinations": ["centralWorkspace"]
                    })
            
            # Build destinations - construct the full workspace resource ID
            # The Log Analytics template outputs the workspace name, we need to build the full resource ID
            workspace_name = getattr(self, '_log_workspace_name', 'blacksmith-logs')
            destinations = {
                "logAnalytics": [{
                    "workspaceResourceId": f"[concat(subscription().id, '/resourceGroups/', resourceGroup().name, '/providers/Microsoft.OperationalInsights/workspaces/', reference('deployLogAnalyticsWorkspace').outputs.workspaceName_output.value)]",
                    "name": "centralWorkspace"
                }]
            }
            
            # Create DCR directly (no DCE needed for standard Windows logs)
            dcr_resource = {
                "type": "Microsoft.Insights/dataCollectionRules",
                "apiVersion": "2021-04-01",
                "name": dcr_name,
                "kind": "Windows",
                "location": "[parameters('location')]",
                "dependsOn": [
                    "[resourceId('Microsoft.Resources/deployments', 'deployLogAnalyticsWorkspace')]"
                ],
                "properties": {
                    "dataSources": data_sources,
                    "destinations": destinations,
                    "dataFlows": data_flows
                }
            }
            
            self.template["resources"].append(dcr_resource)
            dcr_ids.append({
                "name": dcr_name,
                "id": f"[resourceId('Microsoft.Insights/dataCollectionRules', '{dcr_name}')]",
                "targets": dcr.get('targets', [])
            })
        
        return dcr_ids
    
    def _add_azure_monitor_agents(self, logging_config: Dict[str, Any], dcr_ids: List[Dict[str, Any]]):
        """
        Install Azure Monitor Agents on VMs via extension.
        
        Args:
            logging_config: Logging configuration dictionary
            dcr_ids: List of DCR information dictionaries
        """
        vms = self.config.get('virtual_machines', [])
        
        # Collect all target VMs across all DCRs
        for dcr_info in dcr_ids:
            dcr_name = dcr_info['name']
            dcr_targets = dcr_info['targets']
            
            # Determine which VMs to install agents on and expand for multiple instances
            vm_instances = []
            has_workstations = False
            for vm in vms:
                # Check if this VM should have the agent installed
                # Use suffix if available, otherwise use name
                vm_identifier = vm.get('suffix') or vm.get('name')
                if dcr_targets and vm_identifier not in dcr_targets:
                    continue
                
                # Track if we're targeting workstations
                is_workstation = vm.get('type') == 'windows_desktop' and vm.get('role') != 'domain_controller'
                if is_workstation:
                    has_workstations = True
                
                # Generate instance names for all VMs with this config
                count = vm.get('count', 1)
                for i in range(count):
                    if is_workstation:
                        # Workstations use Win10 template naming: prefix + ip_suffix
                        # e.g., "dev" + "10" = "dev10"
                        vm_network = vm.get('network', {})
                        private_ip = vm_network.get('ip_start') or vm_network.get('private_ip', '192.168.1.5')
                        ip_suffix = int(private_ip.split('.')[-1])
                        suffix = vm.get('suffix', '')
                        if suffix:
                            instance_name = f"{suffix}{ip_suffix + i}"
                        else:
                            configured_name = vm.get('name', 'WORKSTATION')
                            import re
                            match = re.match(r'^(.+?)(\d+)$', configured_name)
                            if match:
                                instance_name = f"{match.group(1)}{int(match.group(2)) + i}"
                            else:
                                instance_name = f"{configured_name}{ip_suffix + i}"
                    else:
                        # Regular VMs use our standard naming
                        instance_name = self._generate_vm_name(vm, i)
                    
                    vm_instances.append({"vmName": instance_name})
            
            if not vm_instances:
                continue
            
            target_vms = vm_instances
            
            # Build dependencies for agent installation
            agent_dependencies = [
                f"[resourceId('Microsoft.Insights/dataCollectionRules', '{dcr_name}')]"
            ]
            
            # If targeting workstations, depend on workstation deployment
            if has_workstations:
                agent_dependencies.append("[resourceId('Microsoft.Resources/deployments', 'deployWorkstations')]")
            
            # Add dependency on domain join if AD is enabled
            ad_config = self.config.get('active_directory', {})
            if ad_config.get('enabled') and has_workstations:
                agent_dependencies.append("[resourceId('Microsoft.Resources/deployments', 'JoinWorkstations')]")
            
            # Deploy Azure Monitor Agent extension
            agent_deployment = {
                "type": "Microsoft.Resources/deployments",
                "apiVersion": "2021-04-01",
                "name": f"installAzureMonitorAgents-{dcr_name}",
                "dependsOn": agent_dependencies,
                "properties": {
                    "mode": "Incremental",
                    "templateLink": {
                        "uri": "https://raw.githubusercontent.com/OTRF/Blacksmith/master/templates/azure/Azure-Monitor-Agents/windows.json",
                        "contentVersion": "1.0.0.0"
                    },
                    "parameters": {
                        "virtualMachines": {
                            "value": target_vms
                        },
                        "monitorAgent": {
                            "value": "Azure Monitor Agent"
                        },
                        "location": {
                            "value": "[parameters('location')]"
                        }
                    }
                }
            }
            
            self.template["resources"].append(agent_deployment)
    
    def _add_dcr_associations(self, logging_config: Dict[str, Any], dcr_ids: List[Dict[str, Any]]):
        """
        Create DCR associations which automatically install Azure Monitor Agent.
        
        Args:
            logging_config: Logging configuration dictionary
            dcr_ids: List of DCR information dictionaries
        """
        vms = self.config.get('virtual_machines', [])
        
        # Create DCR associations for each DCR
        for dcr_info in dcr_ids:
            dcr_name = dcr_info['name']
            dcr_targets = dcr_info['targets']
            
            # Determine which VMs to associate
            if not dcr_targets:
                target_vms = vms
            else:
                # Check both suffix and name for matching
                target_vms = [vm for vm in vms if (vm.get('suffix') or vm.get('name')) in dcr_targets]
            
            if not target_vms:
                continue
            
            # Create association for each VM instance
            for vm in target_vms:
                count = vm.get('count', 1)
                is_workstation = vm.get('type') == 'windows_desktop' and vm.get('role') != 'domain_controller'
                
                # Create associations for all instances of this VM
                for i in range(count):
                    if is_workstation:
                        # Workstations use Win10 template naming: prefix + ip_suffix
                        vm_network = vm.get('network', {})
                        private_ip = vm_network.get('ip_start') or vm_network.get('private_ip', '192.168.1.5')
                        ip_suffix = int(private_ip.split('.')[-1])
                        suffix = vm.get('suffix', '')
                        if suffix:
                            instance_name = f"{suffix}{ip_suffix + i}"
                        else:
                            configured_name = vm.get('name', 'WORKSTATION')
                            import re
                            match = re.match(r'^(.+?)(\d+)$', configured_name)
                            if match:
                                instance_name = f"{match.group(1)}{int(match.group(2)) + i}"
                            else:
                                instance_name = f"{configured_name}{ip_suffix + i}"
                    else:
                        # Regular VMs use our standard naming
                        instance_name = self._generate_vm_name(vm, i)
                    
                    # Build dependencies - check if VM is created directly or via nested deployment
                    association_dependencies = [
                        f"[resourceId('Microsoft.Insights/dataCollectionRules', '{dcr_name}')]",
                        f"[resourceId('Microsoft.Resources/deployments', 'installAzureMonitorAgents-{dcr_name}')]"
                    ]
                    
                    # If VM is a workstation (created via nested deployment), depend on that deployment
                    # Otherwise depend on the VM resource directly
                    if is_workstation:
                        association_dependencies.append("[resourceId('Microsoft.Resources/deployments', 'deployWorkstations')]")
                        # Add dependency on workstation domain join if AD is enabled
                        ad_config = self.config.get('active_directory', {})
                        if ad_config.get('enabled'):
                            association_dependencies.append("[resourceId('Microsoft.Resources/deployments', 'JoinWorkstations')]")
                    else:
                        # Server VM - depend on the VM and its domain join extension
                        association_dependencies.append(f"[resourceId('Microsoft.Compute/virtualMachines', '{instance_name}')]")
                        # Add dependency on server domain join extension if AD is enabled
                        # BUT skip domain controller - it doesn't join the domain, it creates it
                        ad_config = self.config.get('active_directory', {})
                        if ad_config.get('enabled') and vm.get('role') != 'domain_controller':
                            association_dependencies.append(f"[resourceId('Microsoft.Compute/virtualMachines/extensions', '{instance_name}', 'JoinDomain')]")
                    
                    # Create DCR association - this will automatically install Azure Monitor Agent
                    association = {
                        "type": "Microsoft.Insights/dataCollectionRuleAssociations",
                        "apiVersion": "2021-04-01",
                        "name": f"{instance_name}-{dcr_name}-association",
                        "scope": f"[resourceId('Microsoft.Compute/virtualMachines', '{instance_name}')]",
                        "dependsOn": association_dependencies,
                        "properties": {
                            "dataCollectionRuleId": dcr_info['id']
                        }
                    }
                    
                    self.template["resources"].append(association)
    
    def save_template(self, output_path: str):
        """
        Save the template to a file.
        
        Args:
            output_path: Path to save the template
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.template, f, indent=2)