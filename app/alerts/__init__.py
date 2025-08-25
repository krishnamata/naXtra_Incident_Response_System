from flask import Blueprint

alerts_bp = Blueprint('alerts', __name__, template_folder='templates')

from . import routes  # ensures routes are registered
