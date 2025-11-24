from flask import Flask
from flask_cors import CORS
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from werkzeug.security import generate_password_hash, check_password_hash
from application.config import LocalDevlopmentConfig
from application.database import db
from application.models import User, Role


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fraud_detection.db'
    app.config.from_object(LocalDevlopmentConfig)
    
    CORS(app, 
         resources={r"/api/*": {
             "origins": [
                 "http://localhost:5173",
                 "https://fraud-finder-frontend-ffw3-7b28r0jlt.vercel.app/",
                 
                 "https://*.vercel.app"  # Allow all Vercel preview deployments
             ],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "Authentication-Token"],
             "supports_credentials": True,
             "expose_headers": ["Authentication-Token"]
         }})
    
    db.init_app(app)
    datastore = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(app, datastore)
    
    # Add after_request handler INSIDE create_app, not in with block
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    
    # Import and register blueprints INSIDE create_app
    from application.routes import api_bp
    api_bp.security = app.security
    app.register_blueprint(api_bp)
    
    return app    


app = create_app()    


with app.app_context():
    db.create_all()  # Create database tables if they don't exist
    
    app.security.datastore.find_or_create_role(name='admin')
    app.security.datastore.find_or_create_role(name='user')
    db.session.commit() 

    if not app.security.datastore.find_user(email='admin@123.com'):
        admin_user = app.security.datastore.create_user(
            email='admin@123.com', 
            username='admin', 
            password=generate_password_hash('admin123'), 
            roles=['admin', 'user']
        )
        db.session.commit()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
