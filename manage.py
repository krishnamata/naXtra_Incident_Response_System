# manage.py

from flask.cli import FlaskGroup
from flask_migrate import Migrate
from app.main import app
from app.extensions import db
from app.models.log_entry import LogEntry  # include other models if needed

migrate = Migrate(app, db)
cli = FlaskGroup(app)

if __name__ == "__main__":
    cli()
