"""
Configuration management for VulnMind
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from vulnmind.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VulnMindConfig:
    """Main configuration class for VulnMind"""
    
    # Scanning settings
    max_concurrent_requests: int = 10
    request_timeout: int = 30
    user_agent: str = "VulnMind/1.0"
    default_scan_depth: str = "medium"
    follow_redirects: bool = True
    verify_ssl: bool = True
    
    # AI settings
    ai_enabled: bool = False
    openai_api_key: Optional[str] = None
    ai_model: str = "gpt-4"
    ai_temperature: float = 0.1
    
    # Self-awareness settings
    learning_rate: float = 0.1
    adaptation_threshold: float = 0.7
    memory_size: int = 1000
    confidence_threshold: float = 0.5
    
    # Plugin settings
    enabled_plugins: list = None
    disabled_plugins: list = None
    plugin_configs: Dict[str, Dict[str, Any]] = None
    
    # Logging settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Report settings
    default_report_format: str = "json"
    report_directory: str = "./reports"
    
    def __post_init__(self):
        """Initialize default values"""
        if self.enabled_plugins is None:
            self.enabled_plugins = []
        if self.disabled_plugins is None:
            self.disabled_plugins = []
        if self.plugin_configs is None:
            self.plugin_configs = {}


def load_config(config_path: str = None) -> VulnMindConfig:
    """Load configuration from file or environment"""
    config = VulnMindConfig()
    
    # Load from file if specified
    if config_path and Path(config_path).exists():
        config = load_config_file(config_path)
    
    # Override with environment variables
    config = load_env_config(config)
    
    return config


def load_config_file(config_path: str) -> VulnMindConfig:
    """Load configuration from file"""
    config_file = Path(config_path)
    
    try:
        if config_file.suffix.lower() in ['.yml', '.yaml']:
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
        elif config_file.suffix.lower() == '.json':
            with open(config_file, 'r') as f:
                data = json.load(f)
        else:
            raise ValueError(f"Unsupported config file format: {config_file.suffix}")
        
        # Create config object from data
        config = VulnMindConfig(**data)
        logger.info(f"Loaded configuration from {config_path}")
        
        return config
        
    except Exception as e:
        logger.error(f"Failed to load config file {config_path}: {str(e)}")
        return VulnMindConfig()


def load_env_config(config: VulnMindConfig) -> VulnMindConfig:
    """Load configuration from environment variables"""
    
    env_mappings = {
        'VULNMIND_MAX_CONCURRENT_REQUESTS': ('max_concurrent_requests', int),
        'VULNMIND_REQUEST_TIMEOUT': ('request_timeout', int),
        'VULNMIND_USER_AGENT': ('user_agent', str),
        'VULNMIND_SCAN_DEPTH': ('default_scan_depth', str),
        'VULNMIND_FOLLOW_REDIRECTS': ('follow_redirects', bool),
        'VULNMIND_VERIFY_SSL': ('verify_ssl', bool),
        
        'VULNMIND_AI_ENABLED': ('ai_enabled', bool),
        'OPENAI_API_KEY': ('openai_api_key', str),
        'VULNMIND_AI_MODEL': ('ai_model', str),
        'VULNMIND_AI_TEMPERATURE': ('ai_temperature', float),
        
        'VULNMIND_LEARNING_RATE': ('learning_rate', float),
        'VULNMIND_ADAPTATION_THRESHOLD': ('adaptation_threshold', float),
        'VULNMIND_MEMORY_SIZE': ('memory_size', int),
        'VULNMIND_CONFIDENCE_THRESHOLD': ('confidence_threshold', float),
        
        'VULNMIND_LOG_LEVEL': ('log_level', str),
        'VULNMIND_LOG_FILE': ('log_file', str),
        
        'VULNMIND_REPORT_FORMAT': ('default_report_format', str),
        'VULNMIND_REPORT_DIR': ('report_directory', str),
    }
    
    for env_var, (attr_name, attr_type) in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            try:
                if attr_type == bool:
                    value = env_value.lower() in ['true', '1', 'yes', 'on']
                elif attr_type == int:
                    value = int(env_value)
                elif attr_type == float:
                    value = float(env_value)
                else:
                    value = env_value
                
                setattr(config, attr_name, value)
                
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid value for {env_var}: {env_value} ({str(e)})")
    
    return config


def save_config(config: VulnMindConfig, config_path: str):
    """Save configuration to file"""
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        data = asdict(config)
        
        if config_file.suffix.lower() in ['.yml', '.yaml']:
            with open(config_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, indent=2)
        elif config_file.suffix.lower() == '.json':
            with open(config_file, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported config file format: {config_file.suffix}")
        
        logger.info(f"Configuration saved to {config_path}")
        
    except Exception as e:
        logger.error(f"Failed to save config file {config_path}: {str(e)}")


def create_default_config(config_path: str = "vulnmind.yml"):
    """Create default configuration file"""
    config = VulnMindConfig()
    save_config(config, config_path)


def validate_config(config: VulnMindConfig) -> bool:
    """Validate configuration values"""
    valid = True
    
    # Validate concurrent requests
    if not 1 <= config.max_concurrent_requests <= 100:
        logger.error("max_concurrent_requests must be between 1 and 100")
        valid = False
    
    # Validate timeout
    if not 1 <= config.request_timeout <= 300:
        logger.error("request_timeout must be between 1 and 300 seconds")
        valid = False
    
    # Validate scan depth
    if config.default_scan_depth not in ['basic', 'medium', 'deep']:
        logger.error("default_scan_depth must be 'basic', 'medium', or 'deep'")
        valid = False
    
    # Validate AI settings
    if config.ai_enabled and not config.openai_api_key:
        logger.warning("AI enabled but no OpenAI API key provided")
    
    if not 0.0 <= config.ai_temperature <= 2.0:
        logger.error("ai_temperature must be between 0.0 and 2.0")
        valid = False
    
    # Validate self-awareness settings
    if not 0.01 <= config.learning_rate <= 1.0:
        logger.error("learning_rate must be between 0.01 and 1.0")
        valid = False
    
    if not 0.1 <= config.adaptation_threshold <= 1.0:
        logger.error("adaptation_threshold must be between 0.1 and 1.0")
        valid = False
    
    if not 10 <= config.memory_size <= 10000:
        logger.error("memory_size must be between 10 and 10000")
        valid = False
    
    if not 0.1 <= config.confidence_threshold <= 1.0:
        logger.error("confidence_threshold must be between 0.1 and 1.0")
        valid = False
    
    # Validate log level
    if config.log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        logger.error("log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        valid = False
    
    # Validate report format
    if config.default_report_format not in ['json', 'html']:
        logger.error("default_report_format must be 'json' or 'html'")
        valid = False
    
    return valid
