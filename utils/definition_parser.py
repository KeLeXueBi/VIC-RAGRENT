import json
from typing import Dict

from models.impl.role_definition import RoleDefinition


class DefinitionParser:
    """
    Utility class for loading and parsing role definitions from a JSON file.

    This parser converts raw JSON configuration into structured RoleDefinition
    objects, which are later used to dynamically construct prompts and control
    agent behavior.
    """

    _roles: Dict[str, RoleDefinition] = {}

    def __init__(self, config_path):
        """
        Initialize the parser.

        Args:
            config_path (str): Path to the role definition JSON file.
        """
        self._config_path = config_path
        self._data = None

    def __enter__(self):
        """
        Load and parse the role definitions.

        Returns:
            DefinitionParser: The parser instance with populated roles.
        """
        self._data = json.load(open(self._config_path))
        self._parse()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Load and parse the role definitions.

        Returns:
            DefinitionParser: The parser instance with populated roles.
        """
        pass

    def _parse(self):
        """
        Convert raw JSON data into RoleDefinition objects.
        """
        for k, v in self._data.items():
            o = RoleDefinition(**v)
            o.role_key = k
            self._roles[k] = o

    @property
    def roles(self):
        """
        Get parsed role definitions.

        Returns:
            Dict[str, RoleDefinition]: Mapping from role_key to RoleDefinition.
        """
        return self._roles


if __name__ == "__main__":
    # Example usage for debugging
    with DefinitionParser('../data/role_definition.json') as d:
        print(d.roles)
