from flask import Blueprint

# create blueprint with the name used in templates: 'nasa_bp'
nasa_bp = Blueprint('nasa_bp', __name__, 
                    template_folder='templates',
                    static_folder='static',
                    static_url_path='/nasa/static')

# ensure routes are imported so decorators run
from . import routes  # noqa


