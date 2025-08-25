from flask import Flask, render_template, session
from app.dashboard.routes import dashboard_bp, config_bp  # import both from routes.py
from app.extensions import db
from app.models import User
from app.auth.routes import auth_bp
from app.agents.routes import agents_bp
from app.api.routes import api_bp
from app.alerts.routes import alerts_bp
from app.routes.agent_logs import agent_bp
import os

#basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.secret_key = 'naxtraSOAR-key'  # Use a secure secret in prod
RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'soar.db')

#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
# ✅ Context processor defined here, where app exists

print("DB URI:", app.config['SQLALCHEMY_DATABASE_URI'])

@app.context_processor
def inject_session():
    return dict(session=session)


app.register_blueprint(auth_bp)
app.register_blueprint(api_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(config_bp)
app.register_blueprint(agents_bp, url_prefix='/download')
app.register_blueprint(alerts_bp)
app.register_blueprint(agent_bp)
@app.cli.command('create-admin')
def create_admin():
    username = input('Username: ')
    password = input('Password: ')
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print('Admin created.')


#@app.route('/test')
#def test():
#   return render_template('test.html')


if __name__ == '__main__':
  with app.app_context():
        db.create_all()    

  app.run(host='0.0.0.0', port=5001, debug=True)

