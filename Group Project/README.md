# Flask Authentication and MFA Project

This project is a Flask-based web application that provides user authentication and multi-factor authentication (MFA) features. It includes user registration, login, and a secure dashboard accessible only to authenticated users.

## Table of Contents

- [Flask Authentication and MFA Project](#flask-authentication-and-mfa-project)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Project Structure](#project-structure)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Routes](#routes)

## Features

- User Registration
- User Login
- Multi-Factor Authentication (MFA) Setup and Challenge
- Secure Dashboard
- User List (Admin View)
- Flash Messages for User Feedback
- Rate Limiting

## Project Structure

```plaintext
.
├── .gitignore
├── app/
│   ├── __init__.py
│   ├── forms.py
│   ├── models.py
│   ├── routes.py
│   ├── static/
│   │   └── js/
│   │       └── registration_validation.js
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── list_users.html
│   │   ├── login.html
│   │   ├── mfa_setup.html
│   │   ├── mfa.html
│   │   └── register.html
│   └── utils/
│       ├── decorators.py
│       ├── register_users.py
│       ├── security.py
│       └── validators.py
├── config.py
├── README.md
├── requirements.txt
└── run.py
```

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/dvorakman/csci262-group-project.git
    cd csci262-group-project
    ```

2. **Create a virtual environment:**
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
    Create a `.env` file in the root directory and add the following:
    ```env
    FLASK_APP=run.py
    FLASK_ENV=development
    SECRET_KEY=your_secret_key
    PEPPER=your_pepper
    ```

5. **Run the application:**
    ```sh
    python run.py
    ```

## Usage

- **Register a new user:** Navigate to `/register` and fill out the registration form.
- **Login:** Navigate to `/login` and enter your credentials.
- **Set up MFA:** After logging in, navigate to `/mfa-setup` to set up multi-factor authentication.
- **Access the dashboard:** Navigate to `/dashboard` to access the secure dashboard.
- **List users:** Navigate to `/list_users` to view the list of registered users (debug).

## Routes

- **`/`**: Home page
- **`/login`**: User login page
- **`/register`**: User registration page
- **`/mfa-setup/<user_id>`**: MFA setup page (requires login)
- **`/mfa`**: MFA challenge page (requires login)
- **`/dashboard`**: Secure dashboard (requires login and MFA)
- **`/list_users`**: List of registered users (debug)
- **`/logout`**: Logout the current user
