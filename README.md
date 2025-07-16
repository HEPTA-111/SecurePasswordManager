# Secure Password Manager

This is a simple but secure web-based password manager application built with Python and Flask. |

## Core Security Features

* **Master Password Security:** User master passwords are never stored. Instead, they are hashed using the strong, modern **Argon2** algorithm with a unique salt for each user.
* **Credential Encryption:** All stored usernames and passwords are encrypted in the database using **AES-256 in GCM mode**. The encryption key is derived from the user's master password and is never stored.
* **SQL Injection Prevention:** All database queries are parameterized using SQLAlchemy, which is the standard best practice for preventing SQL injection attacks.
* **Cross-Site Request Forgery (CSRF) Protection:** The application uses `Flask-WTF` to generate and validate anti-CSRF tokens for all forms, preventing attackers from tricking users into performing unwanted actions.
* **Secure Password Generation:** Includes a built-in password generator to help users create strong, random passwords.

## Setup and Execution Instructions (Windows PowerShell)

Follow these steps carefully to set up and run the project on your local machine.

### Step 1: Create and Activate a Virtual Environment

A virtual environment keeps the project's dependencies isolated from your system's global Python installation.

1.  **Open PowerShell** and navigate to the `SecurePasswordManager` project directory.

    ```powershell
    cd path\to\your\SecurePasswordManager
    ```

2.  **Create the virtual environment.** We will name it `venv`.

    ```powershell
    python -m venv venv
    ```

3.  **Activate the virtual environment.** You must do this every time you work on the project.

    ```powershell
    .\venv\Scripts\Activate.ps1
    ```

    If you get an error about execution policies, you may need to run this command first (as Administrator) and then try activating again:
    `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

    Your PowerShell prompt should now start with `(venv)`.

### Step 2: Install Required Packages

Install all the necessary Python libraries from the `requirements.txt` file.

```powershell
pip install -r requirements.txt
```

### Step 3: Initialize the Database

This command will create the `passwords.db` file and the necessary tables. You only need to run this once.

```powershell
python init_db.py
```
You should see a message: `Database initialized.`

### Step 4: Run the Application

Start the Flask development server.

```powershell
flask run
```

You will see output similar to this:
```
 * Running on [http://127.0.0.1:5000](http://127.0.0.1:5000)
Press CTRL+C to quit
```

### Step 5: Test the Application

1.  Open your web browser and go to **http://127.0.0.1:5000**.
2.  You should see the login page. Click the link to **Register a new account**.
3.  Create an account with a username and a strong master password.
4.  After registering, you will be redirected to the login page. Log in with your new credentials.
5.  You should now be on the dashboard. From here, you can add, view, and manage your passwords.

To stop the application, go back to your PowerShell window and press **CTRL+C**.
