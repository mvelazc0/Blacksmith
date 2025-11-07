"""
Blacksmith - Dynamic Azure Lab Environment Builder

A modular framework for deploying security research lab environments in Azure
using declarative YAML configuration files.
"""

__version__ = "2.0.0"
__author__ = "OTRF Community"
__license__ = "GPL-3.0"

from .config_loader import ConfigLoader
from .validator import ConfigValidator
from .orchestrator import Orchestrator
from .template_builder import TemplateBuilder

__all__ = [
    "ConfigLoader",
    "ConfigValidator",
    "Orchestrator",
    "TemplateBuilder",
]