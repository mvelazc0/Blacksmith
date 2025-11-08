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
        
        # Virtual Network
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
                }
            }
        }
        resources.append(vnet_resource)
        
        # Subnets (including Bastion subnet if needed)
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
        
        for subnet in subnets_to_create:
            subnet_resource = {
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "apiVersion": "2021-05-01",
                "name": f"[concat(variables('virtualNetworkName'), '/', '{subnet.get('name')}')]",
                "dependsOn": [
                    "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]"
                ],
                "properties": {
                    "addressPrefix": subnet.get('address_prefix')
                }
            }
            resources.append(subnet_resource)
        
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
                
            vm_name = vm.get('name')
            vm_type = vm.get('type')
            count = vm.get('count', 1)
            
            # For VMs with count > 1, create multiple instances
            for i in range(count):
                if count > 1:
                    instance_name = f"{vm_name}{i + int(vm.get('network', {}).get('ip_start', '5').split('.')[-1])}"
                else:
                    instance_name = vm_name
                
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
    
    def _create_nic_resource(self, vm: Dict[str, Any], instance_name: str, index: int) -> Dict[str, Any]:
        """Create network interface resource."""
        network = self.config.get('network', {})
        vm_network = vm.get('network', {})
        subnet_name = vm_network.get('subnet', 'default')
        
        # Calculate IP address
        if vm.get('count', 1) > 1:
            ip_start = vm_network.get('ip_start', '192.168.1.5')
            ip_parts = ip_start.split('.')
            ip_parts[-1] = str(int(ip_parts[-1]) + index)
            private_ip = '.'.join(ip_parts)
        else:
            private_ip = vm_network.get('private_ip', '192.168.1.10')
        
        nic = {
            "type": "Microsoft.Network/networkInterfaces",
            "apiVersion": "2021-05-01",
            "name": f"nic-{instance_name}",
            "location": "[parameters('location')]",
            "dependsOn": [
                "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('virtualNetworkName'), '" + subnet_name + "')]"
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
        
        # Add identity if specified
        identity = vm.get('identity', {})
        if identity.get('type') and identity.get('type') != 'None':
            vm_resource["identity"] = {"type": identity.get('type')}
        
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
                "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('virtualNetworkName'), 'AzureBastionSubnet')]"
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
                
                # Step 4: Join workstations to domain (workstations created via nested deployment handle their own prep)
                self._add_domain_join_deployment(dc_name, dc_ip, ad_config)
    
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
            
            vm_name = vm.get('name')
            count = vm.get('count', 1)
            vm_network = vm.get('network', {})
            
            # Handle multiple instances
            for i in range(count):
                if count > 1:
                    instance_name = f"{vm_name}{i + int(vm_network.get('ip_start', '5').split('.')[-1])}"
                else:
                    instance_name = vm_name
                
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
        vm_name_prefix = workstation.get('name', 'WORKSTATION')
        
        # Get IP configuration
        vm_network = workstation.get('network', {})
        subnet_name = vm_network.get('subnet', 'default')
        
        # Get private IP and extract suffix
        private_ip = vm_network.get('private_ip', '192.168.1.5')
        ip_suffix = int(private_ip.split('.')[-1])
        
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
            "[resourceId('Microsoft.Network/virtualNetworks', variables('virtualNetworkName'))]",
            "[resourceId('Microsoft.Network/virtualNetworks/subnets', variables('virtualNetworkName'), '" + subnet_name + "')]"
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
                        "value": ip_suffix
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
            vm_name = vm.get('name')
            count = vm.get('count', 1)
            
            # Handle multiple instances
            for i in range(count):
                if count > 1:
                    instance_name = f"{vm_name}{i + int(vm.get('network', {}).get('ip_start', '5').split('.')[-1])}"
                else:
                    instance_name = vm_name
                
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
    
    def save_template(self, output_path: str):
        """
        Save the template to a file.
        
        Args:
            output_path: Path to save the template
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.template, f, indent=2)