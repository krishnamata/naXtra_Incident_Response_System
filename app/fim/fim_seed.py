import os
from datetime import datetime
from app import create_app
from app.extensions import db
from app.fim.fim_services import add_baseline

def seed_baseline(paths=None):
    """Seed baseline dynamically. Accept list of files or directories."""
    if paths is None:
        paths = []  # Default: empty. Admin can pass directories/files.

    app = create_app()
    with app.app_context():
        for path in paths:
            if os.path.isfile(path):
                add_baseline(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for f in files:
                        add_baseline(os.path.join(root, f))
            else:
                print(f"[WARN] Skipping invalid path: {path}")
        print("✅ Baseline seeding complete.")

if __name__ == "__main__":
    # Example: pass directories/files to seed
    critical_paths = [
        "/etc",           # Linux config files
        "/usr/bin",       # System executables
        "/var/www"        # Web application files
    ]
    seed_baseline(critical_paths)
