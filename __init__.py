from flask import Flask

def create_app():
    app = Flask(__name__)
    # ...existing config...

    # Register the NASA blueprint at the correct prefix
    from nasa import nasa_bp
    app.register_blueprint(nasa_bp, url_prefix='/aquaponics/nasa')

    return app