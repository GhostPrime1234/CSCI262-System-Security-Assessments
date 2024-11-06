# CSCI262_Assignment1
 
Simple File System with User Authentication

--- Overview ---

This Python script implements a simple file system with user authentication and access control, utilising MD5 hashing for password security. 
The system stores user credentials using a salt and shadow mechanism and ensures that files can only be accessed by users with the appropriate clearance levels.

--- Features ---

- **User Creation**: Create new users with a username, password, and clearance level (0 to 3). Each user's password is salted and hashed before being stored.
- **User Authentication**: Authenticate users using their username and password. The system checks the credentials against stored hashes and salts.
- **File Management:** Users can create, read, write, and append to files. Access is controlled based on the user's clearance level.
- **File Listing**: List all files in the system with their associated owners and clearance levels.
- **File Storage**: All file metadata is stored in a `Files.store` file. User credentials are stored in `salt.txt` and `shadow.txt`.

--- Problem Reduction and Implementation Strategy ---
The task was reduced to several key components to ensure precise, modular, and efficient implementation.

1. User Management System:
    - **Salt and Shadow Mechanism:** The problem of secure password storage was addressed by implementing a salt and shadow mechanism. User passwords are concatenated with a randomly generated salt and then hashed using the MD5 algorithm. This method prevents dictionary attacks and ensures secure storage in `salt.txt` and `shadow.txt`.
    - **User Authentication:** The system verifies user credentials by retrieving the salt from `salt.txt`, hashing the provided password with the salt, and comparing the result with the stored hash in `shadow.txt`. This ensures secure and accurate user authentication.
2. File System Operations:
    - **Access Control Model:** The file operations are controlled by a four-level access model inspired by the Bell-LaPadula model. Enforcing access restrictions is reduced to comparing user clearance levels and file classification levels, ensuring that users can only interact with files at their clearance level or lower.
	- **Internal File Management:** Instead of implementing a full-fledged file system, the problem was reduced to maintaining an internal data structure (list or dictionary) to store file metadata, including filenames, owners, and clearance levels. The simplification allows for efficient in-memory management 
3. Code Structure:
	- The code was structured into distinct functions for user management, file operations and access control to ensure modularity and ease of maintenance. Each function addresses a specific part of the task, making the program easy to understand, test and extend.

--- Requirements ---

- Python 3.6.9

--- Installation ---

1. Clone or download this repository to your local machine.
2. Ensure that Python 3.6.9 is installed on your system.

--- Usage ---

------ Running the Script ------

To run the script, use the following command:

```bash
python3 Filesystem.py
```

------ User Creation ------

To create a new user, run the script with the `-i` flag:

```bash
python3 file_system.py -i
```

Follow the prompts to enter the username, password, confirm password, and clearance level.

------ Authentication and File Operations ------

Upon running the script without any flags, you'll be prompted to log in with a username and password. After successful authentication, you'll be presented with several options:

- **(C)reate**: Create a new file.
- **(A)ppend**: Append content to an existing file.
- **(R)ead**: Read the contents of an existing file.
- **(W)rite**: Overwrite the contents of an existing file.
- **(L)ist**: List all files in the system with their owners and clearance levels.
- **(S)ave**: Save the current file system state.
- **(E)xit**: Exit the file system.

------ Access Control ------

- Each file has an owner and a clearance level.
- Users can only read, write, or append to files if their clearance level meets or exceeds the file's clearance level.

--- Important Files ---

- **Filesystem.py**: The main script.
- **salt.txt**: Stores usernames and their associated salts.
- **shadow.txt**: Stores usernames, salted and hashed passwords, and clearance levels.
- **Files.store**: Stores file metadata, including filename, owner, and clearance level.