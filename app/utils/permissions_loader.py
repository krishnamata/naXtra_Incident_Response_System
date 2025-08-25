import os
import yaml


role_permissions = {}

# Path to your role_permissions.yaml file
ROLE_PERMISSIONS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),  # current directory (utils)
    '..', 'config', 'role_permissions.yaml'
)

def load_role_permissions():
    """
    Load role permissions from the YAML file.
    Returns the full dictionary parsed from YAML.
    """
    with open(ROLE_PERMISSIONS_PATH, 'r') as file:
        permissions = yaml.safe_load(file)
    return permissions

def get_permissions_for_role(role_name):
    return role_permissions.get("roles", {}).get(role_name, {})
