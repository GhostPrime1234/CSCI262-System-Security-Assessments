from wtforms.validators import ValidationError
import re

def has_uppercase(form, field):
    if not re.search(r'[A-Z]', field.data):
        raise ValidationError('Password must contain at least one uppercase letter.')

def has_lowercase(form, field):
    if not re.search(r'[a-z]', field.data):
        raise ValidationError('Password must contain at least one lowercase letter.')

def has_digit(form, field):
    if not re.search(r'\d', field.data):
        raise ValidationError('Password must contain at least one digit.')

def has_special(form, field):
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', field.data):
        raise ValidationError('Password must contain at least one special character.')

def no_spaces(form, field):
    if re.search(r'\s', field.data):
        raise ValidationError('Password must not contain spaces.')

def valid_email(form, field):
    email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_pattern, field.data):
        raise ValidationError('Invalid email address.')