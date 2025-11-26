"""
Configuration Validator Module

Validates YAML configuration against the schema and performs semantic validation.
"""

import re
from pathlib import Path
from typing import Dict, Any, List, Tuple
import yaml
import jsonschema
from jsonschema import validate, ValidationError


class ConfigValidator:
    """Validate configuration files against schema and business rules."""
    
    def __init__(self, schema_path: str = None):
        """
        Initialize the ConfigValidator.
        
        Args:
            schema_path: Path to the JSON schema file
        """
        if schema_path is None:
            # Try multiple methods to find the schema file
            schema_path = self._find_schema_file()
        
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def _find_schema_file(self) -> Path:
        """Find the schema file using multiple fallback methods."""
        # Method 1: Try importlib.resources (Python 3.7+)
        try:
            import importlib.resources as pkg_resources
            # For Python 3.9+
            if hasattr(pkg_resources, 'files'):
                schema_path = pkg_resources.files('blacksmith').parent / 'config' / 'schemas' / 'lab-config.schema.yaml'
                if schema_path.exists():
                    return schema_path
        except (ImportError, AttributeError, TypeError):
            pass
        
        # Method 2: Try pkg_resources (older method)
        try:
            import pkg_resources
            schema_path = Path(pkg_resources.resource_filename(
                __name__.split('.')[0],
                '../config/schemas/lab-config.schema.yaml'
            ))
            if schema_path.exists():
                return schema_path
        except:
            pass
        
        # Method 3: Relative to this file (development mode)
        base_dir = Path(__file__).parent.parent.parent
        schema_path = base_dir / "config" / "schemas" / "lab-config.schema.yaml"
        if schema_path.exists():
            return schema_path
        
        # Method 4: Check current working directory
        cwd_schema = Path.cwd() / "config" / "schemas" / "lab-config.schema.yaml"
        if cwd_schema.exists():
            return cwd_schema
        
        # If all methods fail, return the expected path and let it fail with a clear error
        raise FileNotFoundError(
            f"Could not find schema file. Tried:\n"
            f"  - Package resources\n"
            f"  - {base_dir / 'config' / 'schemas' / 'lab-config.schema.yaml'}\n"
            f"  - {cwd_schema}\n"
            f"Please ensure Blacksmith is properly installed or run from the project root."
        )
    
    def _load_schema(self) -> Dict[str, Any]:
        """Load the JSON schema from file."""
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
        
        with open(self.schema_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Validate configuration against schema and business rules.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        # Schema validation
        try:
            validate(instance=config, schema=self.schema)
        except ValidationError as e:
            self.errors.append(f"Schema validation error: {e.message}")
            return False, self.errors, self.warnings
        
        # Semantic validation
        self._validate_network(config)
        self._validate_virtual_machines(config)
        self._validate_dependencies(config)
        self._validate_active_directory(config)
        self._validate_services(config)
        self._validate_security_software(config)
        self._validate_ip_addresses(config)
        
        # Multi-domain validation (if domains are defined)
        if 'domains' in config:
            self._validate_multi_domain(config)
            self._validate_domain_subnets(config)
            self._validate_trusts(config)
            self._validate_cross_domain_groups(config)
        
        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings
    
    def _validate_network(self, config: Dict[str, Any]):
        """Validate network configuration."""
        network = config.get('network', {})
        
        # Validate subnet ranges are within VNet range
        vnet_range = network.get('address_space', '')
        subnets = network.get('subnets', [])
        
        for subnet in subnets:
            subnet_range = subnet.get('address_prefix', '')
            if not self._is_subnet_in_vnet(subnet_range, vnet_range):
                self.errors.append(
                    f"Subnet {subnet.get('name')} range {subnet_range} "
                    f"is not within VNet range {vnet_range}"
                )
    
    def _generate_vm_name_for_validation(self, vm: Dict[str, Any], index: int) -> str:
        """Generate VM name for validation (matches template_builder logic)."""
        base_name = vm.get('name', '')
        suffix = vm.get('suffix', '')
        naming_pattern = vm.get('naming_pattern', 'suffix-number')
        count = vm.get('count', 1)
        
        # Determine the prefix to use
        if suffix:
            prefix = suffix
        elif base_name:
            prefix = base_name
        else:
            prefix = 'VM'
        
        # If count is 1 and we have a name (not suffix), just use the name as-is
        if count == 1 and base_name and not suffix:
            return base_name
        
        # Generate number with zero-padding
        if count < 10:
            number = f"{(index + 1):02d}"  # Always use 2 digits for consistency (01-09)
        elif count < 100:
            number = f"{(index + 1):02d}"
        else:
            number = f"{(index + 1):03d}"
        
        # Apply naming pattern
        if naming_pattern == 'suffix-number':
            return f"{prefix}{number}"
        elif naming_pattern == 'number-suffix':
            return f"{number}{prefix}"
        elif naming_pattern == 'suffix-only':
            return f"{prefix}{(index + 1)}"
        else:
            return f"{prefix}{number}"
    
    def _validate_virtual_machines(self, config: Dict[str, Any]):
        """Validate virtual machine configurations."""
        vms = config.get('virtual_machines', [])
        vm_names = set()
        
        for vm in vms:
            count = vm.get('count', 1)
            
            # Generate all instance names and check for duplicates
            for i in range(count):
                generated_name = self._generate_vm_name_for_validation(vm, i)
                if generated_name in vm_names:
                    self.errors.append(f"Duplicate or conflicting VM name: {generated_name}")
                vm_names.add(generated_name)
                
                # Validate VM name length (Azure limit is 15 for Windows)
                if vm.get('type') in ['windows_server', 'windows_desktop']:
                    if len(generated_name) > 15:
                        self.errors.append(
                            f"Windows VM name '{generated_name}' exceeds 15 character limit"
                        )
            
            # Validate subnet exists
            subnet_name = vm.get('network', {}).get('subnet')
            if subnet_name:
                subnets = config.get('network', {}).get('subnets', [])
                subnet_names = [s.get('name') for s in subnets]
                if subnet_name not in subnet_names:
                    self.errors.append(
                        f"VM '{vm_name}' references non-existent subnet '{subnet_name}'"
                    )
    
    def _validate_dependencies(self, config: Dict[str, Any]):
        """Validate VM dependencies."""
        vms = config.get('virtual_machines', [])
        # Collect all possible VM identifiers (name or suffix)
        vm_identifiers = {vm.get('suffix') or vm.get('name') for vm in vms}
        
        for vm in vms:
            depends_on = vm.get('depends_on', [])
            vm_identifier = vm.get('suffix') or vm.get('name')
            for dep in depends_on:
                if dep not in vm_identifiers:
                    self.errors.append(
                        f"VM '{vm_identifier}' depends on non-existent VM '{dep}'"
                    )
        
        # Check for circular dependencies
        if self._has_circular_dependencies(vms):
            self.errors.append("Circular dependency detected in VM dependencies")
    
    def _validate_active_directory(self, config: Dict[str, Any]):
        """Validate Active Directory configuration."""
        ad_config = config.get('active_directory', {})
        
        if not ad_config.get('enabled', False):
            return
        
        # Check if there's a domain controller
        vms = config.get('virtual_machines', [])
        has_dc = any(vm.get('role') == 'domain_controller' for vm in vms)
        
        if not has_dc:
            self.errors.append(
                "Active Directory is enabled but no domain controller VM is defined"
            )
        
        # Validate domain FQDN format
        domain_fqdn = ad_config.get('domain_fqdn', '')
        if domain_fqdn and not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', domain_fqdn):
            self.errors.append(f"Invalid domain FQDN format: {domain_fqdn}")
        
        # Validate user accounts
        users = ad_config.get('users', [])
        sam_accounts = set()
        for user in users:
            sam = user.get('sam_account', '')
            if sam in sam_accounts:
                self.errors.append(f"Duplicate SAM account name: {sam}")
            sam_accounts.add(sam)
    
    def _validate_services(self, config: Dict[str, Any]):
        """Validate service configurations."""
        services = config.get('services', {})
        vms = config.get('virtual_machines', [])
        # Use suffix or name as identifier
        vm_identifiers = {vm.get('suffix') or vm.get('name') for vm in vms}
        vm_roles = {(vm.get('suffix') or vm.get('name')): vm.get('role') for vm in vms}
        
        # Validate ADFS
        adfs = services.get('adfs', {})
        if adfs.get('enabled', False):
            adfs_server = adfs.get('server')
            if adfs_server and adfs_server not in vm_identifiers:
                self.errors.append(
                    f"ADFS server '{adfs_server}' not found in VM definitions"
                )
            elif adfs_server and vm_roles.get(adfs_server) != 'adfs':
                self.warnings.append(
                    f"ADFS server '{adfs_server}' does not have role 'adfs'"
                )
        
        # Validate WEC
        wec = services.get('wec', {})
        if wec.get('enabled', False):
            wec_server = wec.get('server')
            if wec_server and wec_server not in vm_identifiers:
                self.errors.append(
                    f"WEC server '{wec_server}' not found in VM definitions"
                )
            elif wec_server and vm_roles.get(wec_server) != 'wec':
                self.warnings.append(
                    f"WEC server '{wec_server}' does not have role 'wec'"
                )
        
        # Validate Exchange
        exchange = services.get('exchange', {})
        if exchange.get('enabled', False):
            exchange_server = exchange.get('server')
            if exchange_server and exchange_server not in vm_identifiers:
                self.errors.append(
                    f"Exchange server '{exchange_server}' not found in VM definitions"
                )
    def _validate_security_software(self, config: Dict[str, Any]):
        """Validate security software configurations."""
        security_config = config.get('security_software', {})
        
        if not security_config:
            return
        
        vms = config.get('virtual_machines', [])
        vm_identifiers = {vm.get('suffix') or vm.get('name') for vm in vms}
        vm_roles = {(vm.get('suffix') or vm.get('name')): vm.get('role') for vm in vms}
        vm_types = {(vm.get('suffix') or vm.get('name')): vm.get('type') for vm in vms}
        
        # Validate MDE configuration
        mde_config = security_config.get('mde', {})
        if mde_config.get('enabled', False):
            # Check onboarding package URL is provided
            package_url = mde_config.get('onboarding_package_url')
            if not package_url:
                self.errors.append(
                    "MDE is enabled but 'onboarding_package_url' is not provided"
                )
            elif package_url:
                # Validate URL format
                if not self._is_valid_url(package_url):
                    self.errors.append(
                        f"Invalid MDE onboarding package URL format: {package_url}"
                    )
            
            # Validate targets configuration
            targets_config = mde_config.get('targets', {})
            if targets_config:
                # Validate include list
                include_list = targets_config.get('include', [])
                for target in include_list:
                    if target not in vm_identifiers:
                        self.errors.append(
                            f"MDE target VM '{target}' in include list not found in VM definitions"
                        )
                
                # Validate exclude list
                exclude_list = targets_config.get('exclude', [])
                for target in exclude_list:
                    if target not in vm_identifiers:
                        self.errors.append(
                            f"MDE target VM '{target}' in exclude list not found in VM definitions"
                        )
                
                # Check for conflicts (VM in both include and exclude)
                conflicts = set(include_list) & set(exclude_list)
                if conflicts:
                    self.errors.append(
                        f"MDE targeting conflict: VMs in both include and exclude lists: {', '.join(conflicts)}"
                    )
                
                # Validate types
                valid_types = ['domain_controller', 'member_server', 'workstation']
                include_types = targets_config.get('include_types', [])
                for vm_type in include_types:
                    if vm_type not in valid_types:
                        self.errors.append(
                            f"Invalid MDE target type '{vm_type}'. Valid types: {', '.join(valid_types)}"
                        )
                
                exclude_types = targets_config.get('exclude_types', [])
                for vm_type in exclude_types:
                    if vm_type not in valid_types:
                        self.errors.append(
                            f"Invalid MDE target type '{vm_type}'. Valid types: {', '.join(valid_types)}"
                        )
                
                # Check for type conflicts
                type_conflicts = set(include_types) & set(exclude_types)
                if type_conflicts:
                    self.errors.append(
                        f"MDE targeting conflict: Types in both include and exclude: {', '.join(type_conflicts)}"
                    )
                
                # Validate roles
                valid_roles = ['domain_controller', 'member_server', 'workstation', 'adfs', 'wec', 'exchange']
                include_roles = targets_config.get('include_roles', [])
                for role in include_roles:
                    if role not in valid_roles:
                        self.errors.append(
                            f"Invalid MDE target role '{role}'. Valid roles: {', '.join(valid_roles)}"
                        )
                
                exclude_roles = targets_config.get('exclude_roles', [])
                for role in exclude_roles:
                    if role not in valid_roles:
                        self.errors.append(
                            f"Invalid MDE target role '{role}'. Valid roles: {', '.join(valid_roles)}"
                        )
                
                # Check for role conflicts
                role_conflicts = set(include_roles) & set(exclude_roles)
                if role_conflicts:
                    self.errors.append(
                        f"MDE targeting conflict: Roles in both include and exclude: {', '.join(role_conflicts)}"
                    )
                
                # Validate name patterns
                include_names = targets_config.get('include_names', [])
                exclude_names = targets_config.get('exclude_names', [])
                
                # Check for name pattern conflicts
                name_conflicts = set(include_names) & set(exclude_names)
                if name_conflicts:
                    self.errors.append(
                        f"MDE targeting conflict: Name patterns in both include and exclude: {', '.join(name_conflicts)}"
                    )
                
                # Warn if no targets will be selected
                if not any([include_list, include_types, include_roles, include_names]):
                    # If no include filters, all VMs are targeted (unless excluded)
                    if exclude_list or exclude_types or exclude_roles or exclude_names:
                        # Some VMs will be excluded, which is fine
                        pass
                    else:
                        # No filters at all - all VMs will get MDE
                        self.warnings.append(
                            "MDE has no targeting filters - will be deployed to all VMs"
                        )
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        if not url:
            return False
        # Basic URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    
    def _validate_ip_addresses(self, config: Dict[str, Any]):
        """Validate IP address assignments."""
        vms = config.get('virtual_machines', [])
        used_ips = set()
        
        for vm in vms:
            network = vm.get('network', {})
            private_ip = network.get('private_ip')
            
            if private_ip:
                if private_ip in used_ips:
                    self.errors.append(f"Duplicate IP address: {private_ip}")
                used_ips.add(private_ip)
                
                # Validate IP is in correct subnet
                subnet_name = network.get('subnet')
                if subnet_name:
                    subnets = config.get('network', {}).get('subnets', [])
                    subnet = next((s for s in subnets if s.get('name') == subnet_name), None)
                    if subnet:
                        subnet_range = subnet.get('address_prefix', '')
                        if not self._is_ip_in_subnet(private_ip, subnet_range):
                            self.errors.append(
                                f"IP {private_ip} for VM '{vm.get('name')}' "
                                f"is not in subnet range {subnet_range}"
                            )
    
    def _is_subnet_in_vnet(self, subnet_cidr: str, vnet_cidr: str) -> bool:
        """Check if subnet CIDR is within VNet CIDR."""
        # Simplified check - in production, use ipaddress module
        try:
            import ipaddress
            subnet = ipaddress.ip_network(subnet_cidr, strict=False)
            vnet = ipaddress.ip_network(vnet_cidr, strict=False)
            return subnet.subnet_of(vnet)
        except:
            return True  # Skip validation if ipaddress not available
    
    def _is_ip_in_subnet(self, ip: str, subnet_cidr: str) -> bool:
        """Check if IP address is within subnet CIDR."""
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            subnet = ipaddress.ip_network(subnet_cidr, strict=False)
            return ip_addr in subnet
        except:
            return True  # Skip validation if ipaddress not available
    
    def _has_circular_dependencies(self, vms: List[Dict[str, Any]]) -> bool:
        """Check for circular dependencies in VM definitions."""
        # Build dependency graph using suffix or name as identifier
        graph = {}
        for vm in vms:
            vm_identifier = vm.get('suffix') or vm.get('name')
            depends_on = vm.get('depends_on', [])
            graph[vm_identifier] = depends_on
        
        # DFS to detect cycles
        visited = set()
        rec_stack = set()
        
        def has_cycle(node):
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for vm_name in graph:
            if vm_name not in visited:
                if has_cycle(vm_name):
                    return True
        
        return False
    
    def get_errors(self) -> List[str]:
        """Get validation errors."""
        return self.errors
    
    def get_warnings(self) -> List[str]:
        """Get validation warnings."""
        return self.warnings
    
    def _validate_multi_domain(self, config: Dict[str, Any]):
        """Validate multi-domain configuration."""
        domains = config.get('domains', [])
        vms = config.get('virtual_machines', [])
        vm_identifiers = {vm.get('suffix') or vm.get('name') for vm in vms}
        
        # Check for duplicate domain names
        domain_names = [d['name'] for d in domains]
        if len(domain_names) != len(set(domain_names)):
            self.errors.append("Duplicate domain names found")
        
        # Validate parent-child relationships
        for domain in domains:
            if domain['type'] == 'child_domain':
                parent = domain.get('parent')
                if not parent:
                    self.errors.append(
                        f"Child domain '{domain['name']}' must specify a parent domain"
                    )
                elif parent not in domain_names:
                    self.errors.append(
                        f"Child domain '{domain['name']}' references non-existent parent '{parent}'"
                    )
                else:
                    # Check parent is a forest_root
                    parent_domain = next((d for d in domains if d['name'] == parent), None)
                    if parent_domain and parent_domain['type'] != 'forest_root':
                        self.errors.append(
                            f"Parent domain '{parent}' must be a forest_root, not '{parent_domain['type']}'"
                        )
        
        # Validate DC VMs exist
        for domain in domains:
            dc_vm = domain['dc_vm']
            if dc_vm not in vm_identifiers:
                self.errors.append(
                    f"Domain '{domain['name']}' references non-existent DC VM '{dc_vm}'"
                )
        
        # Validate endpoint assignments
        for domain in domains:
            endpoints = domain.get('endpoints', [])
            for endpoint in endpoints:
                if endpoint not in vm_identifiers:
                    self.errors.append(
                        f"Domain '{domain['name']}' endpoint '{endpoint}' not found in VM definitions"
                    )
        
        # Check for circular parent-child relationships
        if self._has_circular_domain_dependencies(domains):
            self.errors.append("Circular parent-child relationship detected in domains")
    
    def _validate_domain_subnets(self, config: Dict[str, Any]):
        """Validate domain subnet configurations."""
        network = config.get('network', {})
        vnet_range = network.get('address_space', '')
        domains = config.get('domains', [])
        
        # Collect all subnet ranges (global + domain-specific)
        all_subnets = []
        global_subnets = network.get('subnets', [])
        all_subnets.extend(global_subnets)
        
        for domain in domains:
            domain_subnets = domain.get('subnets', [])
            all_subnets.extend(domain_subnets)
        
        # Check for duplicate subnet names
        subnet_names = [s.get('name') for s in all_subnets]
        duplicates = [name for name in subnet_names if subnet_names.count(name) > 1]
        if duplicates:
            self.errors.append(
                f"Duplicate subnet names found: {', '.join(set(duplicates))}"
            )
        
        # Check for overlapping subnet ranges
        for i, subnet1 in enumerate(all_subnets):
            for subnet2 in all_subnets[i+1:]:
                if self._subnets_overlap(
                    subnet1.get('address_prefix', ''),
                    subnet2.get('address_prefix', '')
                ):
                    self.errors.append(
                        f"Subnets '{subnet1.get('name')}' and '{subnet2.get('name')}' have overlapping address ranges"
                    )
        
        # Validate all subnets are within VNet range
        for subnet in all_subnets:
            subnet_range = subnet.get('address_prefix', '')
            if subnet_range and vnet_range:
                if not self._is_subnet_in_vnet(subnet_range, vnet_range):
                    self.errors.append(
                        f"Subnet '{subnet.get('name')}' range {subnet_range} is not within VNet range {vnet_range}"
                    )
        
        # Validate subnet assignment references
        for domain in domains:
            subnet_assignment = domain.get('subnet_assignment', {})
            domain_subnet_names = [s.get('name') for s in domain.get('subnets', [])]
            
            for vm_type, subnet_name in subnet_assignment.items():
                if subnet_name not in subnet_names:
                    self.errors.append(
                        f"Domain '{domain['name']}' subnet assignment references non-existent subnet '{subnet_name}'"
                    )
    
    def _validate_trusts(self, config: Dict[str, Any]):
        """Validate trust configurations."""
        trusts = config.get('trusts', [])
        domains = config.get('domains', [])
        domain_names = [d['name'] for d in domains]
        
        for trust in trusts:
            source = trust['source']
            target = trust['target']
            trust_type = trust['type']
            
            # Validate source and target domains exist
            if source not in domain_names:
                self.errors.append(
                    f"Trust source domain '{source}' not found in domain definitions"
                )
            if target not in domain_names:
                self.errors.append(
                    f"Trust target domain '{target}' not found in domain definitions"
                )
            
            # Validate trust type compatibility
            if source in domain_names and target in domain_names:
                source_domain = next((d for d in domains if d['name'] == source), None)
                target_domain = next((d for d in domains if d['name'] == target), None)
                
                if trust_type == 'forest':
                    # Forest trusts require both to be forest roots
                    if source_domain['type'] != 'forest_root':
                        self.errors.append(
                            f"Forest trust source '{source}' must be a forest_root"
                        )
                    if target_domain['type'] != 'forest_root':
                        self.errors.append(
                            f"Forest trust target '{target}' must be a forest_root"
                        )
                
                # Check if trust is redundant (parent-child already have implicit trust)
                if self._is_same_forest(source, target, domains):
                    self.warnings.append(
                        f"Trust between '{source}' and '{target}' may be redundant - they are in the same forest"
                    )
    
    def _validate_cross_domain_groups(self, config: Dict[str, Any]):
        """Validate cross-domain group targeting."""
        domains = config.get('domains', [])
        trusts = config.get('trusts', [])
        
        # Build trust map
        trust_map = {}
        for trust in trusts:
            source = trust['source']
            target = trust['target']
            if source not in trust_map:
                trust_map[source] = []
            trust_map[source].append(target)
            
            # Bidirectional trusts work both ways
            if trust['direction'] == 'bidirectional':
                if target not in trust_map:
                    trust_map[target] = []
                trust_map[target].append(source)
        
        # Check each group's cross-domain targets
        for domain in domains:
            domain_fqdn = domain['name']
            groups = domain.get('groups', [])
            
            for group in groups:
                local_admin_on = group.get('local_admin_on', [])
                
                for target in local_admin_on:
                    target_domain = target.get('domain')
                    
                    # If targeting different domain, check trust exists
                    if target_domain and target_domain != domain_fqdn:
                        # Check if domains are in same forest (parent-child)
                        if self._is_same_forest(domain_fqdn, target_domain, domains):
                            continue  # Parent-child trust is automatic
                        
                        # Check if explicit trust exists
                        if target_domain not in trust_map.get(domain_fqdn, []):
                            self.errors.append(
                                f"Group '{group['name']}' in domain '{domain_fqdn}' "
                                f"targets domain '{target_domain}' but no trust exists"
                            )
                        
                        # Check group scope for cross-domain
                        if group.get('scope') not in ['Universal', 'Global']:
                            self.warnings.append(
                                f"Group '{group['name']}' targets cross-domain but "
                                f"scope is '{group.get('scope')}'. Consider 'Universal' scope."
                            )
    
    def _is_same_forest(self, domain1: str, domain2: str, domains: List[Dict]) -> bool:
        """Check if two domains are in the same forest (parent-child)."""
        # Find both domains
        d1 = next((d for d in domains if d['name'] == domain1), None)
        d2 = next((d for d in domains if d['name'] == domain2), None)
        
        if not d1 or not d2:
            return False
        
        # Check if one is parent of other
        if d1.get('parent') == domain2 or d2.get('parent') == domain1:
            return True
        
        # Check if they share same forest root
        def get_forest_root(domain):
            if domain['type'] == 'forest_root':
                return domain['name']
            parent = domain.get('parent')
            if parent:
                parent_domain = next((d for d in domains if d['name'] == parent), None)
                if parent_domain:
                    return get_forest_root(parent_domain)
            return None
        
        return get_forest_root(d1) == get_forest_root(d2)
    
    def _has_circular_domain_dependencies(self, domains: List[Dict[str, Any]]) -> bool:
        """Check for circular parent-child relationships in domains."""
        # Build parent-child graph
        graph = {}
        for domain in domains:
            domain_name = domain['name']
            parent = domain.get('parent')
            graph[domain_name] = [parent] if parent else []
        
        # DFS to detect cycles
        visited = set()
        rec_stack = set()
        
        def has_cycle(node):
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in graph.get(node, []):
                if neighbor:  # Skip None values
                    if neighbor not in visited:
                        if has_cycle(neighbor):
                            return True
                    elif neighbor in rec_stack:
                        return True
            
            rec_stack.remove(node)
            return False
        
        for domain_name in graph:
            if domain_name not in visited:
                if has_cycle(domain_name):
                    return True
        
        return False
    
    def _subnets_overlap(self, cidr1: str, cidr2: str) -> bool:
        """Check if two CIDR ranges overlap."""
        if not cidr1 or not cidr2:
            return False
        try:
            import ipaddress
            net1 = ipaddress.ip_network(cidr1, strict=False)
            net2 = ipaddress.ip_network(cidr2, strict=False)
            return net1.overlaps(net2)
        except:
            return False