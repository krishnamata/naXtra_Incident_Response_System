from app import create_app
from app.extensions import db
from app.models import FimBaseline
import os, pwd

app = create_app()
app.app_context().push()

baselines = FimBaseline.query.all()
for b in baselines:
    try:
        if not b.owner:
            b.owner = pwd.getpwuid(os.stat(b.file_path).st_uid).pw_name
        if not b.permissions:
            b.permissions = oct(os.stat(b.file_path).st_mode & 0o777)
    except FileNotFoundError:
        print(f"File not found: {b.file_path}")
        continue

db.session.commit()
print("Existing baselines updated successfully.")
