#!/user/bin/python

import re
from os import path
import hashlib
import random
import string
import sys



def generate_md5(input_string):
    """Generates a md5 hash of a string."""
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    # Encode and update hash with the input string
    md5_hash.update(input_string.encode('utf-8'))
    # Return the hexadecimal digest of the hash

    return md5_hash.hexdigest()


def generate_salt():
    """Generate a random salt of 8 digits."""
    # Generate a string of 8 random digits
    return ''.join(random.choice(string.digits) for _ in range(8))


def validate_password(password):
    """Validate password against security requirements."""
    # Check if the password length is less than 12 characters
    if len(password) < 12:
        print("Password must be at least 12 characters long", file=sys.stderr)

    # Check if the password contains at least one uppercase letter
    if not re.search('[A-Z]', password):
        print("Password must contain at least one uppercase letter.", file=sys.stderr)
        return False

    # Check if the password contains at least one lowercase letter
    if not re.search('[a-z]', password):
        print("Password must contain at least one lowercase letter.", file=sys.stderr)
        return False

    # Check if the password contains at least one number
    if not re.search('[0-9]', password):
        print("Password must contain at least one number", file=sys.stderr)
        return False

    # Check if the password contains at least one special character
    if not re.search(f'[{string.punctuation}]', password):
        print("Password must contain at least one special character.", file=sys.stderr)
        return False

    # If all checks pass, the password is valid
    return True


def check_username_exists(username):
    """Check if a username already exists in the system."""
    # Open the salt file to check for existing usernames
    with open("salt.txt", "r") as salt_file:
        for line in salt_file:
            # Check if the username exists in the file
            # If a line starts with the username followed by ":", the username exists
            if line.startswith(username + ":"):
                return True

    #  Return False if the username is not found
    return False


def print_password_requirements():
    """Print the password security requirements."""
    print("Password requirements:"
          "\n - Must be at least 12 characters long"
          "\n - Must contain at least one uppercase letter"
          "\n - Must contain at least one lowercase letter"
          "\n - Must contain at least one number"
          "\n - Must contain at least one special character")


def get_valid_password():
    """Prompt the user to enter a valid password."""
    while True:
        # Display the password requirements
        print_password_requirements()
        # Prompt the user for a password
        password = input("Enter a password: ")

        # Validate the entered password
        if validate_password(password):
            # If valid, prompt the user to confirm the password
            confirm_password = input("Confirm your password: ")

            # Check if the passwords match
            if password == confirm_password:
                # Return the valid and confirmed passwords
                return password
            else:
                print("Passwords do not match. Please try again.")


def get_user_salt(username: str):
    """Retrieve the salt for a given username."""
    # Open the salt file to find the salt associated with the username
    with open("salt.txt", "r") as salt_file:
        for line in salt_file:
            # Check if the line starts with the username followed by ":"
            if line.startswith(username + ":"):
                # Split the line and return the salt part
                return line.strip().split(":")[1]
    # Return None if the username is not found
    return None


def check_user_credentials(username: str, pass_salt_hash: str):
    """Check the user's credentials against the stored data."""
    # Open the shadow file to verify credentials
    with open("shadow.txt", "r") as shadow_file:
        for line in shadow_file:
            # Split each line into user, stored hash and clearance level.
            user, stored_hash, clearance = line.strip().split(":")
            # Check if the provided username and hash match the stored ones
            if user == username and stored_hash == pass_salt_hash:
                # Return the user's clearance level if credentials are correct
                return clearance
    # Return None if the credentials do not match
    return None


def save_user_data(username: str, salt: str, pass_salt_hash: str, clearance: int):
    """Save the user's salt and hashed password."""
    # Open the salt and shadow files for appending new data
    with open("salt.txt", "a") as salt_file, open("shadow.txt", "a") as shadow_file:
        # Write the username and salt to the file
        salt_file.write(f"{username}:{salt}\n")
        # Write the username, hash and clearance level to the shadow file
        shadow_file.write(f"{username}:{pass_salt_hash}:{clearance}\n")


def create_user():
    """Save the user's salt and hashed password."""
    print("Creating Users:")
    # Prompt the user to enter a username
    username = input("Username: ")

    # Check if the username already exists
    if check_username_exists(username):
        print("Username already exists. Please choose a different username.")
        return False

    # Get a valid user from the user
    password = get_valid_password()

    # Loop until user enters a clearance level that is an integer
    while True:
        try:
            # Prompt the user to enter a clearance level and convert it to an integer
            clearance = input("User clearance (0 or 1 or 2 or 3): ")
            clearance = int(clearance)

            if clearance in [0, 1, 2, 3]:
                break
            else:
                raise ValueError
        except ValueError:
            # Handle invalid input for the clearance level
            print("Please enter a number in (0 or 1 or 2 or 3).")

    # Generate a random salt for the user
    salt = generate_salt()
    # Generate an MD5 hash of the concatenated password and salt
    pass_salt_hash = generate_md5(password + salt)

    # Save the user's data to the salt and shadow files
    save_user_data(username, salt, pass_salt_hash, clearance)

    print(f"User {username} created successfully with clearance level {clearance}.")


def authenticate_user():
    """Authenticate a user."""
    # Prompt for the user to enter their username
    username = input("Username: ")

    # Open the salt file to retrieve the user's salt
    with open("salt.txt", "r") as salt_file:
        salt = None
        for line in salt_file:
            # Check if the line starts with the username followed by ":"
            if line.startswith(username + ":"):
                # Extract the salt from the line
                username, salt = line.strip().split(":")
                break

    # If the salt is not found, the username does not exist
    if salt is None:
        print("Username not found.")
        return None

    print(f"{username} found in salt.txt")
    print(f"salt retrieved: {salt}")

    # Prompt the user to enter their password
    password = input("Password: ")
    # Generate the hash of the concatenated password and salt
    pass_salt_hash = generate_md5(password + salt)

    # Open the shadow file to verify the credentials
    with open("shadow.txt", "r") as shadow_file:
        for line in shadow_file:
            # Split each line into user, stored hash and clearance level
            user, stored_hash, clearance = line.strip().split(":")
            # Check if the provided credentials match the stored ones
            if user == username and stored_hash == pass_salt_hash:  # Check if the credentials match
                print(f"Authentication for user {username} complete.")
                print(f"The clearance for {username} is {clearance}.")
                return username, int(clearance)

    print("Authentication failed. Invalid username or password.")
    return None


def load_files():
    """Load the stored files into memory."""
    # Initialise an empty dictionary for files
    files = {}

    # Check if the Files.store file exists
    if path.exists("Files.store"):
        # Open the file for reading and load the file information into the dictionary
        with open("Files.store", "r") as store_file:
            for line in store_file:
                filename, owner, clearance = line.strip().split(":")
                files[filename] = {'owner': owner, 'clearance': int(clearance)}

    return files


class SimpleFileSystem:
    """A simple file system class to manage files and user permissions."""

    def __init__(self, username, clearance):
        # Store the current user's name
        self.username = username
        # Store the user's clearance level
        self.clearance = clearance
        # Load the stored files into memory
        self.files = load_files()

    def create_file(self, filename):
        """Create a new file in the file system."""
        if filename in self.files:  # Check if the file already exists
            print("File already exists.")
        else:
            # Add the new file to the system with its owner and clearance level
            self.files[filename] = {'owner': self.username, 'clearance': self.clearance}
            print(self.files, self.files.items())
            print("File created successfully.")

    def access_file(self, m_filename, m_username, action):
        """Access a file in the file system based on user clearance and permissions."""
        # Check if the file exists
        if m_filename not in self.files:
            print("File does not exist.")
            return False

        file_info = self.files[m_filename]  # Retrieve the file information

        # Check if the user has sufficient clearance and if the action is allowed
        if self.username != m_username:
            print("Permission denied: Incorrect username.")
            main()

        # Can read down but not up
        if action == 'read' and file_info['clearance'] <= self.clearance:
            self.read_file(m_filename)

        # Can write up but not down
        elif action == 'write' and file_info["clearance"] >= self.clearance:
            self.modify_file(m_filename, action)

        # Can append up but not down
        elif action == 'append' and file_info["clearance"] >= self.clearance:
            self.modify_file(m_filename, action)
        else:
            print(f"Permission denied for {action} operation.")

    @staticmethod
    def read_file(m_filename):
        """Read and display the contents of a file."""
        # Check if the file exists
        try:
            with open(m_filename, "r") as store_file:  # Open the file for reading
                content = store_file.read()
                print(f"Contents of {m_filename}:\n{content}")  # Display the file's contents
            print("File read successfully.")
        except IOError:
            print("File does not exist.")

    @staticmethod
    def modify_file(m_filename, action):
        """Modify a file by writing or appending content."""
        content = input("Enter content to write into the file: ") if action == 'write' \
            else input("Please enter content to append: ")
        mode = 'w' if action == 'write' else 'a'

        try:
            with open(m_filename, mode) as store_file:
                store_file.write(f"{content}\n")  # Write to the file
            print(f"{m_filename} {action} successfully.")
        except IOError:
            print(f"Error {action}ing to {m_filename}.")

    def list_files(self):
        """List all files in the file system."""
        if self.files:
            print("Files in the system.")
            for filename, file_info in self.files.items():
                print("Filename: {filename}, Owner: {owner}, Clearance: {clearance}"
                      .format(filename=filename, owner=file_info['owner'], clearance=file_info['clearance']))
        else:
            print("No files in the system.")

    def save_files(self):
        """Save the file metadata to disk."""
        # Open the Files.store file for writing
        with open("Files.store", "w") as store_file:
            for filename, file_info in self.files:
                # Write the file info to the store
                store_file.write(f"{filename}:{file_info['owner']}:{file_info['clearance']}\n")
        print("Files saved successfully.")


def exit_prog():
    print("Exiting Program.")
    sys.exit(0)


# Main function to start the FileSystem
def main():
    print('MD5 ("This is a test") = {md5}'.format(md5=generate_md5("This is a test")))
    print('Logging into system')

    if len(sys.argv) > 1 and sys.argv[1] == "-i":
        create_user()
        return 0

    # Load existing file system records
    if path.exists("Files.store"):
        print("Loading Files.store...")

    user_info = authenticate_user()
    if not user_info:
        return 1

    username, clearance = user_info
    file_system = SimpleFileSystem(username, clearance)

    while True:
        # Present the user with available options
        print("Options: (C)reate, (A)ppend, (R)ead, (W)rite, (L)ist, (S)ave or (E)xit.")
        option = input("Choose an option: ").strip().lower()

        if option == 'c':
            filename = input("Filename: ").strip()
            file_system.create_file(filename)
        elif option == 'a':
            filename = input("Filename: ").strip()
            file_system.access_file(filename, m_username=username, action='append')
        elif option == 'r':
            filename = input("Filename: ").strip()
            file_system.access_file(filename, m_username=username, action='read')
        elif option == 'w':
            filename = input("Filename: ").strip()
            file_system.access_file(filename, m_username=username, action='write')
        elif option == 'l':
            # List all possible file metadata
            file_system.list_files()
        elif option == 's':
            # Save the file metadata and exit the program
            file_system.save_files()
            print("File system saved.")
            exit_prog()
        elif option == 'e':
            exit_choice = input("Shut down the FileSystem? (Y)es or (N)o: ").strip().lower()
            if exit_choice == 'y':
                exit_prog()
        else:
            print("Invalid option.", file=sys.stderr)


if __name__ == "__main__":
    if not path.exists("salt.txt"):
        open("salt.txt", "w").close()
    if not path.exists("shadow.txt"):
        open("shadow.txt", "w").close()
    try:
        main()
    except KeyboardInterrupt:
        exit_prog()
