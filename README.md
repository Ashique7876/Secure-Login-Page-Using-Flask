
# Flask OTP Verification Web Application

This is a secure user registration and login system built with Flask. It uses OTP (One-Time Password) for registration verification and provides basic user authentication. The application includes several security measures such as SSL, content security policy, rate limiting, and email verification.

## Features

- User Registration with OTP verification
- User Login with hashed password
- Secure User Dashboard
- Logout functionality
- Rate Limiting with Flask-Limiter
- Content Security Policy with Flask-Talisman
- SSL support with Flask-SSLify
- Email-based OTP sending and verification
- Password hashing with Werkzeug
- Environment variable configuration with `dotenv`

## Technologies Used

- **Flask**: A lightweight WSGI web application framework in Python
- **Flask-SQLAlchemy**: SQLAlchemy integration with Flask for database management
- **Flask-Mail**: Email integration for OTP sending
- **Flask-Limiter**: Rate limiting for routes
- **Flask-Talisman**: Implements Content Security Policy and other security headers
- **Flask-SSLify**: Forces SSL/HTTPS for the application
- **Werkzeug**: Password hashing
- **SQLite**: Database used for storing user and OTP information
- **dotenv**: For loading environment variables from a `.env` file

## Requirements

- Python 3.7+
- Flask
- Flask-SQLAlchemy
- Flask-Mail
- Flask-SSLify
- Flask-Talisman
- Flask-Limiter
- python-dotenv
- Markupsafe

## Installation

### 1. Clone the repository:

```bash
git clone https://github.com/your-username/flask-otp-auth.git
cd flask-otp-auth
```

### 2. Set up a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate     # For Windows
```

### 3. Create a `.env` file for environment variables:

Create a `.env` file in the root directory of your project and define the following variables:

```env
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///yourdatabase.db
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False
```

Replace the values with your own:

- `SECRET_KEY`: A secret key used for sessions.
- `SQLALCHEMY_DATABASE_URI`: Your database URI. (For development, use `sqlite:///yourdatabase.db`).
- Email settings for sending OTP emails.

### 4. Run the application:

```bash
python app.py
```

The application will start on `http://localhost:5000` by default.


## Security Features

### 1. **SSL and HTTPS**:
The app uses `Flask-SSLify` to enforce SSL, ensuring the app is only served over HTTPS.

### 2. **Content Security Policy**:
`Flask-Talisman` is configured with a Content Security Policy (CSP) to help protect against cross-site scripting (XSS) and other content injection attacks.

### 3. **Rate Limiting**:
`Flask-Limiter` is used to limit the number of requests a user can make to a specific route, helping to protect against brute-force attacks.

### 4. **Password Hashing**:
The passwords are securely hashed using `Werkzeug`'s `generate_password_hash` and `check_password_hash` functions, ensuring that passwords are not stored in plaintext.

### 5. **OTP Expiry**:
OTP codes expire after 2 minutes to reduce the window for potential abuse.

### 6. **Session Management**:
The app uses Flask sessions to store user information, such as email, username, and login status.

## How OTP Verification Works

1. **User Registration**:
   - The user enters their information (name, email, password).
   - The system sends an OTP to the user's email.
   - The user enters the OTP in the OTP verification page.
   - If the OTP is valid and not expired, the user is registered.

2. **Login**:
   - The user enters their email and password.
   - The system checks the hashed password in the database.
   - If the credentials are correct, the user is logged in and redirected to the dashboard.

## Environment Variables

The application uses environment variables for configuration. Create a `.env` file in the root directory and include the following values:

```env
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///your_database.db
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False
```



## Screenshorts


### Login Page

![image](https://github.com/user-attachments/assets/ea8d484d-a214-48d0-b0be-2f22a32e1561)


### Registration Page

![Screenshot 2024-12-05 003449](https://github.com/user-attachments/assets/31e03bac-e6ac-4887-a920-5e3ee092c3e7)


### OTP Verification

![Screenshot 2024-12-05 003530](https://github.com/user-attachments/assets/4752f81a-5e71-4edf-9109-56c5f2e435a1)


### Dashboard

![Screenshot 2024-12-05 003607](https://github.com/user-attachments/assets/aa1ad73b-ef50-4e63-be5a-06366a31939e)


