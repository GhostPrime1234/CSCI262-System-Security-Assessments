from app import create_app
import atexit

app = create_app()

@atexit.register
def clear_users():
    with app.app_context():
        app.users.clear()
        print("All users have been cleared from memory.")

if __name__ == '__main__':
    app.run(debug=True)