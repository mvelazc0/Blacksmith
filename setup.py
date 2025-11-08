"""
Setup configuration for Blacksmith
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="blacksmith-azure",
    version="2.0.0",
    author="OTRF Community",
    author_email="",
    description="Dynamic Azure Lab Environment Builder for Security Research",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OTRF/Blacksmith",
    project_urls={
        "Bug Tracker": "https://github.com/OTRF/Blacksmith/issues",
        "Documentation": "https://blacksmith.readthedocs.io/",
        "Source Code": "https://github.com/OTRF/Blacksmith",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "PyYAML>=6.0",
        "jsonschema>=4.17.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.2.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "azure": [
            "azure-mgmt-resource>=21.0.0",
            "azure-identity>=1.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "blacksmith=blacksmith.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "config/schemas/*.yaml",
            "config/examples/*.yaml",
        ],
    },
    zip_safe=False,
    keywords=[
        "azure",
        "arm-templates",
        "infrastructure-as-code",
        "security-research",
        "lab-environment",
        "active-directory",
        "windows",
        "linux",
    ],
)