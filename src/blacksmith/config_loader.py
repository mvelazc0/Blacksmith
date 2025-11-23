"""
Configuration Loader Module

Handles loading and parsing YAML configuration files for Blacksmith lab deployments.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import yaml


class ConfigLoader:
    """Load and parse YAML configuration files."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the ConfigLoader.
        
        Args:
            config_path: Path to the YAML configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.base_dir = Path(__file__).parent.parent.parent
        
    def load(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to the YAML configuration file
            
        Returns:
            Dictionary containing the parsed configuration
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML is malformed
        """
        path = config_path or self.config_path
        
        if not path:
            raise ValueError("No configuration path provided")
        
        config_file = Path(path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Error parsing YAML configuration: {e}")
        
        # Resolve relative paths
        self._resolve_paths()
        
        return self.config
    
    def _resolve_paths(self):
        """Resolve relative paths in the configuration."""
        # Add logic to resolve any relative paths in the config
        pass
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation, e.g., 'network.vnet_name')
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network configuration section."""
        return self.config.get('network', {})
    
    def get_vm_config(self) -> list:
        """Get virtual machines configuration section."""
        return self.config.get('virtual_machines', [])
    
    def get_ad_config(self) -> Dict[str, Any]:
        """Get Active Directory configuration section."""
        return self.config.get('active_directory', {})
    
    def get_services_config(self) -> Dict[str, Any]:
        """Get services configuration section."""
        return self.config.get('services', {})
    
    def get_features_config(self) -> Dict[str, Any]:
        """Get features configuration section."""
        return self.config.get('features', {})
    
    def get_credentials(self) -> Dict[str, str]:
        """Get credentials configuration section."""
        return self.config.get('credentials', {})
    
    def get_tags(self) -> Dict[str, str]:
        """Get tags configuration section."""
        return self.config.get('tags', {})
    
    def is_service_enabled(self, service_name: str) -> bool:
        """
        Check if a service is enabled.
        
        Args:
            service_name: Name of the service (e.g., 'adfs', 'wec')
            
        Returns:
            True if service is enabled, False otherwise
        """
        services = self.get_services_config()
        service = services.get(service_name, {})
        return service.get('enabled', False)
    
    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature_name: Name of the feature (e.g., 'sysmon', 'aad_connect')
            
        Returns:
            True if feature is enabled, False otherwise
        """
        features = self.get_features_config()
        feature = features.get(feature_name, {})
        return feature.get('enabled', False)
    
    def get_vm_by_name(self, vm_name: str) -> Optional[Dict[str, Any]]:
        """
        Get VM configuration by name.
        
        Args:
            vm_name: Name of the virtual machine
            
        Returns:
            VM configuration dictionary or None if not found
        """
        vms = self.get_vm_config()
        for vm in vms:
            if vm.get('name') == vm_name:
                return vm
        return None
    
    def get_vms_by_role(self, role: str) -> list:
        """
        Get all VMs with a specific role.
        
        Args:
            role: VM role (e.g., 'domain_controller', 'adfs')
            
        Returns:
            List of VM configurations with the specified role
        """
        vms = self.get_vm_config()
        return [vm for vm in vms if vm.get('role') == role]
    
    def get_vms_by_type(self, vm_type: str) -> list:
        """
        Get all VMs of a specific type.
        
        Args:
            vm_type: VM type (e.g., 'windows_server', 'windows_desktop', 'linux')
            
        Returns:
            List of VM configurations of the specified type
        """
        vms = self.get_vm_config()
        return [vm for vm in vms if vm.get('type') == vm_type]
    
    def validate_structure(self) -> bool:
        """
        Perform basic structure validation.
        
        Returns:
            True if basic structure is valid
            
        Raises:
            ValueError: If required fields are missing
        """
        required_fields = ['name', 'location', 'network', 'credentials', 'virtual_machines']
        
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Required field '{field}' missing from configuration")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Get the full configuration as a dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()
    
    def get_domain_mode(self) -> str:
        """
        Detect the domain configuration mode.
        
        Returns:
            'multi' if using new domains array
            'single' if using legacy active_directory
            'none' if no domain configuration
        """
        if 'domains' in self.config:
            return 'multi'
        elif self.config.get('active_directory', {}).get('enabled'):
            return 'single'
        return 'none'
    
    def is_multi_domain(self) -> bool:
        """
        Check if configuration uses multi-domain mode.
        
        Returns:
            True if using domains array, False otherwise
        """
        return 'domains' in self.config
    
    def get_domains_config(self) -> list:
        """
        Get domains configuration section.
        
        Returns:
            List of domain configurations (empty if not using multi-domain)
        """
        return self.config.get('domains', [])
    
    def get_trusts_config(self) -> list:
        """
        Get trusts configuration section.
        
        Returns:
            List of trust configurations (empty if not defined)
        """
        return self.config.get('trusts', [])
    
    def get_all_subnets(self) -> list:
        """
        Get all subnets (global + domain-specific).
        
        Returns:
            List of all subnet configurations
        """
        subnets = []
        
        # Add global subnets
        network = self.get_network_config()
        subnets.extend(network.get('subnets', []))
        
        # Add domain-specific subnets
        if self.is_multi_domain():
            for domain in self.get_domains_config():
                subnets.extend(domain.get('subnets', []))
        
        return subnets