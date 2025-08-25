import yaml
from app.extensions import db
from app.models import User

ROLE_PERMISSIONS_PATH = '/app/config/role_permissions.yaml'

def update_user_roles():
    with open(ROLE_PERMISSIONS_PATH, 'r') as file:
        roles = yaml.safe_load(file).keys()

    users = User.query.all()
    for user in users:
        if not user.role or user.role not in roles:
            user.role = 'user'  # or assign any default role you prefer
    db.session.commit()
    print("User roles updated based on YAML roles.")

if __name__ == "__main__":
    update_user_roles()
