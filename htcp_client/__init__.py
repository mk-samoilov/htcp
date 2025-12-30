"""
HTCP Client Package

High TCP client library for synchronous TCP communication.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from htcp_client.client import Client
from htcp.backend.proto import Package
from htcp_client import utils

__all__ = ['Client', 'Package', 'utils']
