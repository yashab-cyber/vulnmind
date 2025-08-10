"""
Plugin system initialization
"""

from .base import BasePlugin, ParameterPlugin, HeaderPlugin
from .sql_injection import SQLInjectionPlugin
from .xss import XSSPlugin
from .csrf import CSRFPlugin
from .open_redirect import OpenRedirectPlugin
from .command_injection import CommandInjectionPlugin
from .directory_traversal import DirectoryTraversalPlugin

__all__ = [
    'BasePlugin', 'ParameterPlugin', 'HeaderPlugin',
    'SQLInjectionPlugin', 'XSSPlugin', 'CSRFPlugin',
    'OpenRedirectPlugin', 'CommandInjectionPlugin', 'DirectoryTraversalPlugin'
]

# Registry of all available plugins
AVAILABLE_PLUGINS = {
    'sql_injection': SQLInjectionPlugin,
    'xss': XSSPlugin,
    'csrf': CSRFPlugin,
    'open_redirect': OpenRedirectPlugin,
    'command_injection': CommandInjectionPlugin,
    'directory_traversal': DirectoryTraversalPlugin
}

def get_all_plugins():
    """Get instances of all available plugins"""
    return [plugin_class() for plugin_class in AVAILABLE_PLUGINS.values()]

def get_plugin(plugin_name: str):
    """Get a specific plugin by name"""
    if plugin_name in AVAILABLE_PLUGINS:
        return AVAILABLE_PLUGINS[plugin_name]()
    return None
