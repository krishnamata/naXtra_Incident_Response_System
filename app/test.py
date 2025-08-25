from app.main import app
from app.extensions import db
from app.models import LogEntry, Alert  # import your models

with app.app_context():
    try:
         db.create_all()  # This will create all tables based on your models
         print("Tables created successfully.")
    except Exception as e:
          print("Error creating tables:", e)
