class Config():
    DEBUG = False
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    
class LocalDevlopmentConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///fraud_detection.db'
    DEBUG = True
    
    #config for security
    SECRET_KEY = 'this_is_a_secret_key' # hash user credentials session
    SECURITY_PASSWORD_HASH = 'bcrypt' # hash user passwords
    SECURITY_PASSWORD_SALT = 'this_is_a_salt' #help to hash user passwords
    WTF_CSRF_ENABLED = False 
    SECURITY_TOKEN_AUTHENTICATION_HEADER = 'Authentication-Token'