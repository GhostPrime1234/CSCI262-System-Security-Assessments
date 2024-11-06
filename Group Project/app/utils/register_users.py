from flask import current_app
from config import Config
from app.utils.security import hash_password, verify_password

def register_user(username: str, password: str) -> bool:
    """Register a new user with the given username and password."""
    try:
        
        users = current_app.users

        if username in users:
            print(f"{username} already exists.")
            return False

        
        result = hash_password(password)

        print(f"{username} registered successfully.")

        return True

    except Exception as e:
        print(f"Error during registration: {e}")
        return False

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate the user by checking the provided username and password."""
    try:
        
        with open(Config.USERS_FILE, 'r') as user_file:
            users = {line.strip().split(":")[0]: (line.strip().split(":")[1], line.strip().split(":")[2]) for line in user_file}

        
        if username not in users:
            print(f"{username} does not exist.")
            return False

        
        stored_hash, stored_salt = users[username]

        
        if verify_password(stored_hash, stored_salt, password):
            print(f"{username} successfully authenticated.")
            return True 
        else:
            print(f"{username} authentication failure.")
            return False

    except Exception as e:
        print(f"Error during authentication: {e}")
        return False