#from app.models import RuleIndex
from app.extensions import db

class RuleIndex(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String, nullable=False, index=True)
    title = db.Column(db.String)
    description = db.Column(db.Text)  # ✅ Add this
    severity = db.Column(db.Integer)  # ✅ Add this
    keywords = db.Column(db.String)
    log_type = db.Column(db.String)   # ✅ Add this
    mitre_id = db.Column(db.String)   # ✅ Optional: for MITRE enrichment
    mitre_link = db.Column(db.String) # ✅ Optional: for clickable MITRE URLs
    file_path = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)  # 'rule' or 'decoder'
