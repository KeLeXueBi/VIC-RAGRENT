from typing import Dict
from loguru import logger
import yaml


class ConfigHelper:
    """
    Utility class for loading and accessing configuration from a YAML file.

    This class reads the configuration once during initialization and provides
    a read-only interface for accessing configuration values throughout the system.
    """

    _config = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ...

    def __init__(self, config_path):
        """
        Initialize the configuration helper.

        Args:
            config_path (str): Path to the YAML configuration file.
        """
        self._config_path = config_path
        self._handle()

    def _handle(self):
        """
        Load configuration from the YAML file.

        Errors are logged but not raised, allowing the system to handle missing
        or malformed configurations gracefully.
        """
        try:
            with open(self._config_path, 'r', encoding='utf-8') as f:
                self._config = yaml.load(f, Loader=yaml.FullLoader)
        except Exception as e:
            logger.error(e)

    @property
    def config(self) -> Dict:
        """
        Get the loaded configuration.

        Returns:
            Dict: Parsed configuration dictionary.
        """
        return self._config

# Default global configuration instance
# NOTE: Update this path according to your environment.
default_config = ConfigHelper('/home/root/config.yaml')
