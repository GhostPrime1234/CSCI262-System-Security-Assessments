import os
from os import urandom

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'super_duper_ultra_secret_default_key')
    PEPPER = os.environ.get('PEPPER', urandom(16))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'