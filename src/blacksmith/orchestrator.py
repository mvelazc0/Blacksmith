"""
Orchestrator Module

Coordinates the deployment and management of Azure lab environments.
"""

from typing import Dict, Any, Optional
import subprocess
import json
import os
from pathlib import Path


class Orchestrator:
    """Orchestrate Azure deployments."""
    
    def __init__(self, config: Dict[str, Any], template: Dict[str, Any]):
        """
        Initialize the Orchestrator.
        
        Args:
            config: Parsed configuration dictionary
            template: Generated ARM template
        """
        self.config = config
        self.template = template
        self.subscription_id: Optional[str] = None
        self.deployment_name = f"{config.get('name', 'blacksmith')}-deployment"
        self.resource_group = config.get('resource_group', 'rg-blacksmith')
        self.location = config.get('location', 'eastus')
    
    def set_subscription(self, subscription_id: str):
        """Set the Azure subscription ID."""
        self.subscription_id = subscription_id
    
    def deploy(self, verbose: bool = False) -> bool:
        """
        Deploy the lab environment to Azure.
        
        Args:
            verbose: Enable verbose output
            
        Returns:
            True if deployment succeeded, False otherwise
        """
        try:
            # Check Azure CLI is installed
            if not self._check_azure_cli():
                print("❌ Azure CLI is not installed or not in PATH")
                print("   Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
                return False
            
            # Set subscription if provided
            if self.subscription_id:
                print(f"Setting subscription: {self.subscription_id}")
                self._run_az_command(['account', 'set', '--subscription', self.subscription_id])
            
            # Create resource group
            print(f"Creating resource group: {self.resource_group}")
            self._create_resource_group()
            
            # Save template to temp file (use system temp directory)
            import tempfile
            temp_dir = tempfile.gettempdir()
            
            template_path = Path(temp_dir) / f"{self.deployment_name}.json"
            with open(template_path, 'w') as f:
                json.dump(self.template, f, indent=2)
            
            # Create parameters
            parameters = self._build_parameters()
            params_path = Path(temp_dir) / f"{self.deployment_name}-params.json"
            with open(params_path, 'w') as f:
                json.dump(parameters, f, indent=2)
            
            # Deploy template
            print(f"Starting deployment: {self.deployment_name}")
            cmd = [
                'deployment', 'group', 'create',
                '--resource-group', self.resource_group,
                '--name', self.deployment_name,
                '--template-file', str(template_path),
                '--parameters', str(params_path)
            ]
            
            if verbose:
                cmd.append('--verbose')
            
            result = self._run_az_command(cmd)
            
            # Clean up temp files (Python 3.7 compatible)
            try:
                template_path.unlink()
            except FileNotFoundError:
                pass
            try:
                params_path.unlink()
            except FileNotFoundError:
                pass
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"Deployment error: {e}")
            return False
    
    def destroy(self) -> bool:
        """
        Destroy the lab environment.
        
        Returns:
            True if destruction succeeded, False otherwise
        """
        try:
            print(f"Deleting resource group: {self.resource_group}")
            result = self._run_az_command([
                'group', 'delete',
                '--name', self.resource_group,
                '--yes',
                '--no-wait'
            ])
            return result.returncode == 0
        except Exception as e:
            print(f"Destroy error: {e}")
            return False
    
    def get_deployment_status(self) -> Optional[Dict[str, Any]]:
        """
        Get the status of the deployment.
        
        Returns:
            Deployment status dictionary or None
        """
        try:
            result = self._run_az_command([
                'deployment', 'group', 'show',
                '--resource-group', self.resource_group,
                '--name', self.deployment_name,
                '--output', 'json'
            ], capture_output=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            return None
        except Exception:
            return None
    
    def print_connection_info(self):
        """Print connection information for deployed resources."""
        print("\n" + "="*60)
        print("CONNECTION INFORMATION")
        print("="*60)
        
        print(f"\nResource Group: {self.resource_group}")
        print(f"Location: {self.location}")
        
        # Get VM information
        vms = self.config.get('virtual_machines', [])
        
        if vms:
            print("\nVirtual Machines:")
            for vm in vms:
                vm_name = vm.get('name')
                vm_type = vm.get('type')
                private_ip = vm.get('network', {}).get('private_ip', 'DHCP')
                
                print(f"\n  {vm_name} ({vm_type})")
                print(f"    Private IP: {private_ip}")
                
                # Try to get public IP if available
                remote_access = self.config.get('network', {}).get('remote_access', {})
                if remote_access.get('mode') == 'AllowPublicIP':
                    print(f"    Public IP: Check Azure Portal")
        
        # Print credentials
        creds = self.config.get('credentials', {})
        print(f"\nAdmin Username: {creds.get('admin_username', 'N/A')}")
        print(f"Admin Password: <configured>")
        
        # Print AD info if enabled
        ad_config = self.config.get('active_directory', {})
        if ad_config.get('enabled'):
            print(f"\nActive Directory:")
            print(f"  Domain: {ad_config.get('domain_fqdn', 'N/A')}")
            print(f"  NetBIOS: {ad_config.get('domain_netbios', 'N/A')}")
        
        print("\n" + "="*60)
    
    def _check_azure_cli(self) -> bool:
        """Check if Azure CLI is installed."""
        try:
            # On Windows, try both 'az' and 'az.cmd'
            commands = ['az', 'az.cmd'] if os.name == 'nt' else ['az']
            
            for cmd in commands:
                try:
                    result = subprocess.run(
                        [cmd, '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        shell=True  # Use shell on Windows
                    )
                    if result.returncode == 0:
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            return False
        except Exception:
            return False
    
    def _create_resource_group(self):
        """Create the Azure resource group."""
        self._run_az_command([
            'group', 'create',
            '--name', self.resource_group,
            '--location', self.location
        ])
    
    def _run_az_command(self, args: list, capture_output: bool = False):
        """
        Run an Azure CLI command.
        
        Args:
            args: Command arguments
            capture_output: Whether to capture output
            
        Returns:
            CompletedProcess instance
        """
        # On Windows, use 'az.cmd' or shell=True
        if os.name == 'nt':
            cmd = ['az.cmd'] + args
        else:
            cmd = ['az'] + args
        
        if capture_output:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=(os.name == 'nt')  # Use shell on Windows
            )
        else:
            return subprocess.run(
                cmd,
                timeout=300,
                shell=(os.name == 'nt')  # Use shell on Windows
            )
    
    def _build_parameters(self) -> Dict[str, Any]:
        """
        Build ARM template parameters from configuration.
        
        Returns:
            Parameters dictionary
        """
        creds = self.config.get('credentials', {})
        ad_config = self.config.get('active_directory', {})
        
        parameters = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "adminUsername": {
                    "value": creds.get('admin_username', 'labadmin')
                },
                "adminPassword": {
                    "value": creds.get('admin_password')
                },
                "location": {
                    "value": self.location
                }
            }
        }
        
        # Add AD parameters if enabled
        if ad_config.get('enabled'):
            parameters["parameters"]["domainFQDN"] = {
                "value": ad_config.get('domain_fqdn', 'lab.local')
            }
            parameters["parameters"]["domainNetbiosName"] = {
                "value": ad_config.get('domain_netbios', 'LAB')
            }
        
        return parameters