# parser/__init__.py
# Makes 'parser' a Python package.
# Import the three parser functions for convenient access.

from .ssh_parser import parse_ssh_log
from .apache_parser import parse_apache_log
from .windows_parser import parse_windows_log
