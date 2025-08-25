import os
from flask import g, Flask, session, request, abort, redirect, send_from_directory
#from app.tasks.routes import tasks_bp
from app.routes.naxtraai_routes import naxtraai_bp
from app.config import settings
from app.commands import import_rules_command
from app.extensions import db, mail, migrate
from app.routes.sec_ops import sec_ops_bp
from app.utils.permissions_loader import load_role_permissions
from app.models import User, Alert
from dotenv import load_dotenv
from app.routes.mistral_api import mistral_bp 
from app.routes import server
from app.decoders.loader import load_wazuh_decoders
from app.rules.rules_loader import load_rules
from app.rules.rules_engine import RuleEngine
from app.routes.ai_insights_routes import ai_insights_bp
# Import Blueprints
from app.search.routes import search_bp
from app.dashboard.routes import dashboard_bp
from app.auth.routes import auth_bp
from app.agents.routes import agents_bp
from app.alerts.routes import alerts_bp
from app.api.routes import api_bp
from app.dlp_routes import dlp_bp
from app.playbooks.routes import playbook_bp
from app.routes.agent_logs import agent_bp
import logging
import sys


load_dotenv()
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


DECODERS = load_wazuh_decoders("/home/kali/wazuh-ruleset/decoders")
RULES = load_rules("/var/www/modular-soar/app/rules/wazuh-ruleset/rules")
rule_engine = RuleEngine(RULES)


# === STEP 2: Load permissions at startup ===
role_permissions = load_role_permissions().get('roles', {})

def get_user_permissions():
    role = session.get('role')
    return role_permissions.get(role, [])

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.settings')
      
    
    # Initialize extensions
    db.init_app(app)
 
    migrate.init_app(app, db)
    mail.init_app(app)


    # Register CLI commands
    app.cli.add_command(import_rules_command)

    # Register Blueprints
    app.register_blueprint(search_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(agents_bp, url_prefix='/download')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(dlp_bp)
    app.register_blueprint(playbook_bp, url_prefix='/playbook')
    app.register_blueprint(agent_bp,url_prefix='/api')
    #app.register_blueprint(tasks_bp)
    app.register_blueprint(ai_insights_bp)
    app.register_blueprint(mistral_bp, url_prefix="/ai")
    app.register_blueprint(naxtraai_bp, url_prefix='/api/naxtraai')
    app.register_blueprint(server.bp)
    app.register_blueprint(sec_ops_bp)
   # Context processor to inject username and role into templates
    @app.context_processor
    def inject_user():
        return {
            'username': session.get('username', 'Guest'),
            'role': session.get('role', 'N/A')
        }

    # Optional: before_request to set g.current_user if you want
    @app.before_request
    def load_current_user():
        g.current_user = {
            'username': session.get('username'),
            'role': session.get('role')
        }

    @app.context_processor
    def inject_alert_count():
        if 'user_id' in session:
            count = Alert.query.filter_by(is_new=True).count()
            return {'new_alert_count': count}
        return {}


    #Redirect root URL to dashboard
    @app.route('/')
    def root_redirect():
        return redirect('/dashboard/')

    # Serve favicon
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )


    return app

