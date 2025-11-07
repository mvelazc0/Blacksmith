"""
Template Builder Module

Builds ARM templates from configuration and component modules.
"""

from typing import Dict, Any, List
from pathlib import Path
import json


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
        
        for vm in vms:
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
        """Add service-specific resources and extensions."""
        # This would add DSC extensions, custom script extensions, etc.
        # For now, this is a placeholder for the modular service components
        pass
    
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
    
    def save_template(self, output_path: str):
        """
        Save the template to a file.
        
        Args:
            output_path: Path to save the template
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.template, f, indent=2)