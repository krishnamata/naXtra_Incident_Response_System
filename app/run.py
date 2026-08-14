from app import create_app, db
from app.models import User
from app.rules.rules_loader import load_rules
from app.rules.rules_engine import RuleEngine
from flask import session

app = create_app()
app.config.from_object('app.config.settings')
app.config["api_key"] = "naxtraSOAR-key"
# Load rule engine
rules = load_rules('app/rules/wazuh-ruleset/rules')
app.rule_engine = RuleEngine(rules)


@app.context_processor
def inject_session():
    return dict(session=session)

@app.cli.command('create-admin')
def create_admin():
    username = input('Username: ')
    password = input('Password: ')

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"❌ User '{username}' already exists.")
        return

    user = User(username=username, role='admin')
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print('✅ Admin created.')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
