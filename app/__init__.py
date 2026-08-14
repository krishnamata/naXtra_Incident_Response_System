import os
import sys
import logging
from flask import Flask, g, session, redirect, send_from_directory
from dotenv import load_dotenv

# === Extensions ===
from app.extensions import db, migrate, mail

# === Utilities and Models ===
from app.utils.permissions_loader import load_role_permissions
from app.models import Alert
from app.commands import import_rules_command
from app.decoders.loader import load_wazuh_decoders
from app.rules.rules_loader import load_rules
from app.rules.rules_engine import RuleEngine

# === Load environment variables ===
load_dotenv()
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

# === Load decoders and rules ===
DECODERS = load_wazuh_decoders("/home/kali/wazuh-ruleset/decoders")
RULES = load_rules("/var/www/modular-soar/app/rules/wazuh-ruleset/rules")
rule_engine = RuleEngine(RULES)

# === Load permissions ===
role_permissions = load_role_permissions().get('roles', {})

def get_user_permissions():
    role = session.get('role')
    return role_permissions.get(role, [])

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.settings')
    app.config["api_key"] = "naxtraSOAR-key"

    # === Initialize extensions ===
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # === Register CLI commands ===
    app.cli.add_command(import_rules_command)

    # === Import blueprints locally to avoid circular imports ===
    from app.search.routes import search_bp
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp
    from app.dashboard.routes import dashboard_bp
    from app.agents.routes import agents_bp
    from app.alerts.routes import alerts_bp
    from app.dlp_routes import dlp_bp
    from app.playbooks.routes import playbook_bp
    from app.routes.agent_logs import agent_bp
    from app.alerts.detection_routes import detection_bp
    from app.fim.fim_routes import fim_bp
    from app.routes.ai_insights_routes import ai_insights_bp
    from app.routes.mistral_api import mistral_bp
    from app.routes.naxtraai_routes import naxtraai_bp
    from app.routes import server
    from app.routes.sec_ops import sec_ops_bp
    from app.routes.stats import stats_bp
    from app.audit.audit_routes import audit_bp
    from app.alerts.routes import read_text_file  # import the function
    app.jinja_env.filters['read_text_file'] = read_text_file

    # === Register blueprints ===
    app.register_blueprint(search_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(agents_bp, url_prefix='/download')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(dlp_bp)
    app.register_blueprint(playbook_bp, url_prefix='/playbook')
    app.register_blueprint(agent_bp, url_prefix='/api')
    app.register_blueprint(detection_bp)
    app.register_blueprint(fim_bp, url_prefix='/fim')
    app.register_blueprint(ai_insights_bp)
    app.register_blueprint(mistral_bp, url_prefix="/api/mistral")
    app.register_blueprint(naxtraai_bp, url_prefix='/api/naxtraai')
    app.register_blueprint(server.bp)
    app.register_blueprint(sec_ops_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(audit_bp)

    # === Context processors ===
    @app.context_processor
    def inject_user():
        return {
            'username': session.get('username', 'Guest'),
            'role': session.get('role', 'N/A')
        }

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

    # === Root redirect ===
    @app.route('/')
    def root_redirect():
        return redirect('/dashboard/')

    # === Favicon route ===
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )

    return app

