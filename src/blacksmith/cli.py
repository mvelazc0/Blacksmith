"""
Command Line Interface Module

Provides CLI commands for Blacksmith lab deployment and management.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional
import json

from .config_loader import ConfigLoader
from .validator import ConfigValidator
from .orchestrator import Orchestrator
from .template_builder import TemplateBuilder


class BlacksmithCLI:
    """Command-line interface for Blacksmith."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog='blacksmith',
            description='Blacksmith - Dynamic Azure Lab Environment Builder',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Deploy a lab environment
  blacksmith deploy --config config/examples/win10-ad-adfs.yaml
  
  # Validate configuration
  blacksmith validate --config config/examples/minimal-ad.yaml
  
  # Generate ARM template without deploying
  blacksmith generate --config config/examples/mixed-environment.yaml --output template.json
  
  # List available components
  blacksmith components list
  
  # Destroy a lab environment
  blacksmith destroy --config config/examples/win10-ad-adfs.yaml
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Deploy command
        deploy_parser = subparsers.add_parser(
            'deploy',
            help='Deploy a lab environment'
        )
        deploy_parser.add_argument(
            '--config', '-c',
            required=True,
            help='Path to YAML configuration file'
        )
        deploy_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Validate and generate template without deploying'
        )
        deploy_parser.add_argument(
            '--subscription-id',
            help='Azure subscription ID'
        )
        deploy_parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose output'
        )
        
        # Validate command
        validate_parser = subparsers.add_parser(
            'validate',
            help='Validate configuration file'
        )
        validate_parser.add_argument(
            '--config', '-c',
            required=True,
            help='Path to YAML configuration file'
        )
        
        # Generate command
        generate_parser = subparsers.add_parser(
            'generate',
            help='Generate ARM template from configuration'
        )
        generate_parser.add_argument(
            '--config', '-c',
            required=True,
            help='Path to YAML configuration file'
        )
        generate_parser.add_argument(
            '--output', '-o',
            required=True,
            help='Output path for generated ARM template'
        )
        generate_parser.add_argument(
            '--format',
            choices=['json', 'yaml'],
            default='json',
            help='Output format (default: json)'
        )
        
        # Components command
        components_parser = subparsers.add_parser(
            'components',
            help='Manage components'
        )
        components_subparsers = components_parser.add_subparsers(
            dest='components_command',
            help='Component commands'
        )
        components_subparsers.add_parser('list', help='List available components')
        
        # Destroy command
        destroy_parser = subparsers.add_parser(
            'destroy',
            help='Destroy a lab environment'
        )
        destroy_parser.add_argument(
            '--config', '-c',
            required=True,
            help='Path to YAML configuration file'
        )
        destroy_parser.add_argument(
            '--force',
            action='store_true',
            help='Skip confirmation prompt'
        )
        
        # Version command
        subparsers.add_parser('version', help='Show version information')
        
        return parser
    
    def run(self, args: Optional[list] = None):
        """
        Run the CLI with the given arguments.
        
        Args:
            args: Command-line arguments (defaults to sys.argv[1:])
        """
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return 1
        
        try:
            if parsed_args.command == 'deploy':
                return self._deploy(parsed_args)
            elif parsed_args.command == 'validate':
                return self._validate(parsed_args)
            elif parsed_args.command == 'generate':
                return self._generate(parsed_args)
            elif parsed_args.command == 'components':
                return self._components(parsed_args)
            elif parsed_args.command == 'destroy':
                return self._destroy(parsed_args)
            elif parsed_args.command == 'version':
                return self._version()
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if parsed_args.command == 'deploy' and parsed_args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        
        return 0
    
    def _deploy(self, args) -> int:
        """Handle deploy command."""
        print(f"Loading configuration from {args.config}...")
        
        # Load configuration
        loader = ConfigLoader(args.config)
        config = loader.load()
        
        print(f"Validating configuration...")
        
        # Validate configuration
        validator = ConfigValidator()
        is_valid, errors, warnings = validator.validate(config)
        
        if warnings:
            print("\nWarnings:")
            for warning in warnings:
                print(f"  ⚠️  {warning}")
        
        if not is_valid:
            print("\nValidation failed:")
            for error in errors:
                print(f"  ❌ {error}")
            return 1
        
        print("✅ Configuration is valid")
        
        # Generate template
        print("\nGenerating ARM template...")
        builder = TemplateBuilder(config)
        template = builder.build()
        
        if args.dry_run:
            print("\n✅ Dry run completed successfully")
            print(f"Template would deploy {len(config.get('virtual_machines', []))} VMs")
            return 0
        
        # Deploy
        print("\nDeploying to Azure...")
        orchestrator = Orchestrator(config, template)
        
        if args.subscription_id:
            orchestrator.set_subscription(args.subscription_id)
        
        success = orchestrator.deploy(verbose=args.verbose)
        
        if success:
            print("\n✅ Deployment completed successfully")
            orchestrator.print_connection_info()
            return 0
        else:
            print("\n❌ Deployment failed")
            return 1
    
    def _validate(self, args) -> int:
        """Handle validate command."""
        print(f"Loading configuration from {args.config}...")
        
        # Load configuration
        loader = ConfigLoader(args.config)
        config = loader.load()
        
        print("Validating configuration...")
        
        # Validate
        validator = ConfigValidator()
        is_valid, errors, warnings = validator.validate(config)
        
        if warnings:
            print("\nWarnings:")
            for warning in warnings:
                print(f"  ⚠️  {warning}")
        
        if errors:
            print("\nErrors:")
            for error in errors:
                print(f"  ❌ {error}")
        
        if is_valid:
            print("\n✅ Configuration is valid")
            return 0
        else:
            print("\n❌ Configuration is invalid")
            return 1
    
    def _generate(self, args) -> int:
        """Handle generate command."""
        print(f"Loading configuration from {args.config}...")
        
        try:
            # Load and validate
            loader = ConfigLoader(args.config)
            config = loader.load()
            
            validator = ConfigValidator()
            is_valid, errors, warnings = validator.validate(config)
            
            if not is_valid:
                print("Configuration validation failed:")
                for error in errors:
                    print(f"  ❌ {error}")
                return 1
            
            # Generate template
            print("Generating ARM template...")
            builder = TemplateBuilder(config)
            template = builder.build()
        except Exception as e:
            print(f"\n❌ Error during template generation: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        # Write output
        output_path = Path(args.output)
        
        if args.format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=2)
        else:  # yaml
            import yaml
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(template, f, default_flow_style=False)
        
        print(f"\n✅ Template generated: {output_path}")
        return 0
    
    def _components(self, args) -> int:
        """Handle components command."""
        if args.components_command == 'list':
            print("Available Components:")
            print("\nNetwork Components:")
            print("  - Virtual Network (vnet)")
            print("  - Subnet")
            print("  - Network Security Group (nsg)")
            print("  - Azure Bastion")
            print("\nCompute Components:")
            print("  - Windows Server VM")
            print("  - Windows Desktop VM")
            print("  - Linux VM")
            print("\nService Components:")
            print("  - Active Directory Domain Services")
            print("  - Active Directory Federation Services (ADFS)")
            print("  - Windows Event Collector (WEC)")
            print("  - Microsoft Exchange Server")
            print("\nFeature Components:")
            print("  - Sysmon")
            print("  - Azure AD Connect")
            print("  - Azure Monitor")
            return 0
        
        return 0
    
    def _destroy(self, args) -> int:
        """Handle destroy command."""
        print(f"Loading configuration from {args.config}...")
        
        loader = ConfigLoader(args.config)
        config = loader.load()
        
        resource_group = config.get('resource_group', 'unknown')
        
        if not args.force:
            response = input(
                f"\n⚠️  This will delete resource group '{resource_group}' "
                f"and all resources within it.\n"
                f"Are you sure? (yes/no): "
            )
            if response.lower() != 'yes':
                print("Aborted.")
                return 0
        
        print(f"\nDestroying resource group '{resource_group}'...")
        orchestrator = Orchestrator(config, {})
        
        success = orchestrator.destroy()
        
        if success:
            print("\n✅ Resources destroyed successfully")
            return 0
        else:
            print("\n❌ Destroy operation failed")
            return 1
    
    def _version(self) -> int:
        """Handle version command."""
        from . import __version__, __author__
        print(f"Blacksmith version {__version__}")
        print(f"Author: {__author__}")
        return 0


def main():
    """Main entry point for the CLI."""
    cli = BlacksmithCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()