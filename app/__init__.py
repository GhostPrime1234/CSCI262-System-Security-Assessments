from flask import Flask
from flask_wtf import CSRFProtect

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    # Add CSRF protection
    CSRFProtect(app)

    # Register routes
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    # In-memory user storage
    app.users = {}
    
    return app
