# Personal Finance Management System

## Overview

The Personal Finance Management System is a web application designed to help users manage their finances by tracking income, expenses, and generating financial reports. The application is built with a Flask backend and will have a frontend built with HTML, CSS, and JavaScript.

## Features

- User Authentication: Register, Login, and Logout.
- User Profile Management: Update and delete user profiles.
- Financial Data Management: Add, update, delete, and view financial transactions (income and expenses).
- Reporting: Generate monthly financial reports and visualize data through charts.
- Security Enhancements: Input validation, JWT-based authentication, logging, and monitoring with Sentry.

## Project Structure

finance-management-system/

├── backend/
│ ├── app/
│ │ ├── init.py
│ │ ├── models.py
│ │ ├── routes.py
│ │ ├── config.py
│ │ ├── auth.py
│ ├── migrations/
│ ├── .env
│ ├── run.py
│ ├── requirements.txt
│ ├── README.md
├── frontend/
│ ├── static/
│ │ ├── css/
│ │ │ └── styles.css
│ │ ├── js/
│ │ │ └── scripts.js
│ ├── templates/
│ │ ├── index.html
│ │ ├── login.html
│ │ ├── register.html
│ │ ├── dashboard.html
│ ├── README.md



## Setup Instructions

1. **Backend Setup**:
   - Navigate to the `backend` directory.
   - Create a virtual environment and activate it.
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```
   - Set up the environment variables in the `.env` file.
   - Initialize the database and run migrations:
     ```bash
     flask db init
     flask db migrate -m "Initial migration"
     flask db upgrade
     ```
   - Start the Flask application:
     ```bash
     python run.py
     ```

2. **Frontend Setup**:
   - Navigate to the `frontend` directory.
   - Open the `index.html` file in your web browser.

## API Endpoints

- **User Authentication**:
  - `POST /auth/register`: Register a new user.
  - `POST /auth/login`: Login a user.
  - `PUT /auth/update_profile`: Update user profile.
  - `DELETE /auth/delete_profile`: Delete user profile.

- **Financial Data**:
  - `POST /api/transactions`: Add a new transaction.
  - `GET /api/transactions`: Get all transactions.
  - `PUT /api/transactions/<id>`: Update a transaction.
  - `DELETE /api/transactions/<id>`: Delete a transaction.

- **Reports**:
  - `GET /api/reports`: Get financial reports.
  - `GET /api/report_chart`: Get financial report chart.


## Security

### Password Management
- **Password Hashing**: Passwords are hashed using the `Werkzeug` security module, which employs a strong hashing algorithm to ensure that passwords are stored securely.
- **Password Validation**: Passwords must meet complexity requirements to ensure strong security (e.g., at least 8 characters, containing upper and lower case letters, numbers, and special characters).

### Input Validation
- **Username and Email Validation**: Usernames and emails are validated using regular expressions to ensure they meet the required formats.
- **Data Sanitization**: All input data is sanitized to prevent SQL injection and other common security vulnerabilities.

### Authentication
- **JWT Authentication**: JSON Web Tokens (JWT) are used for user authentication. Tokens are issued upon successful login and are required for accessing protected endpoints.
- **Token Security**: JWT tokens are securely generated and include expiration times to limit the duration of access.

### Logging and Monitoring
- **Logging**: Application logs are managed using `RotatingFileHandler` to ensure that logs are stored efficiently and old logs are archived.
- **Monitoring**: Sentry is integrated for real-time error tracking and monitoring, allowing for quick identification and resolution of issues.


## Contributors

- Zakaria Khiraoui

## License

This project is licensed under the MIT License.
