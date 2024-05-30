from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from itsdangerous import URLSafeTimedSerializer
from .models import User, Transaction, db
import os
import re
import matplotlib.pyplot as plt
import io
from collections import defaultdict  # Add this import
import sentry_sdk
from flask import Flask

sentry_sdk.init(
    dsn="https://06fd6768d225cf913f25696f714f46af@o4507347609518080.ingest.us.sentry.io/4507347612729344",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,
)

app = Flask(__name__)


# Initialize URLSafeTimedSerializer
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

# Define the main blueprint
main = Blueprint('main', __name__)

@main.route('/')
def index():
    return jsonify(message="Welcome to the Personal Finance Management System!")

@main.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Define the auth blueprint
auth = Blueprint('auth', __name__)

def validate_username(username):
    username_regex = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
    return username_regex.match(username)

def validate_email(email):
    email_regex = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return email_regex.match(email)

def validate_password(password):
    password_regex = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$')
    return password_regex.match(password)

@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        current_app.logger.warning('Registration attempt with missing fields')
        return jsonify({'message': 'Missing required fields'}), 400

    if not validate_username(username):
        current_app.logger.warning('Registration attempt with invalid username format')
        return jsonify({'message': 'Invalid username format'}), 400

    if not validate_email(email):
        current_app.logger.warning('Registration attempt with invalid email format')
        return jsonify({'message': 'Invalid email format'}), 400

    if not validate_password(password):
        current_app.logger.warning('Registration attempt with weak password')
        return jsonify({'message': 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character'}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        current_app.logger.warning('Registration attempt with existing username or email')
        return jsonify({'message': 'User already exists'}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    current_app.logger.info(f'User registered: {username}')
    return jsonify({'message': 'User registered successfully'}), 201

@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user is None:
        current_app.logger.warning('Login attempt with non-existent username')
        return jsonify({'message': 'Invalid credentials - user not found'}), 401

    if not user.check_password(password):
        current_app.logger.warning(f'Login attempt with wrong password for user: {username}')
        return jsonify({'message': 'Invalid credentials - wrong password'}), 401

    access_token = create_access_token(identity={'username': user.username, 'email': user.email})
    current_app.logger.info(f'User logged in: {username}')
    return jsonify({'access_token': access_token}), 200

@auth.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        user.set_password(data['password'])

    db.session.commit()

    return jsonify({'message': 'User profile updated successfully'}), 200

@auth.route('/delete_profile', methods=['DELETE'])
@jwt_required()
def delete_profile():
    current_user = get_jwt_identity()
    
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User profile deleted successfully'}), 200

@auth.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    token = s.dumps(email, salt='password-reset-salt')
    # In a real application, you would send the token to the user's email
    return jsonify({'message': 'Password reset token generated', 'token': token}), 200

@auth.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'message': 'The reset link is invalid or has expired'}), 400

    data = request.get_json()
    new_password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password has been reset'}), 200

# Define the transactions blueprint
transactions = Blueprint('transactions', __name__)

@transactions.route('/transactions', methods=['POST'])
@jwt_required()
def create_transaction():
    current_user = get_jwt_identity()
    data = request.get_json()

    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    new_transaction = Transaction(
        user_id=user.id,
        type=data.get('type'),
        amount=data.get('amount'),
        description=data.get('description')
    )

    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({'message': 'Transaction created successfully'}), 201

@transactions.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    transactions = Transaction.query.filter_by(user_id=user.id).all()
    result = []
    for transaction in transactions:
        transaction_data = {
            'id': transaction.id,
            'type': transaction.type,
            'amount': transaction.amount,
            'description': transaction.description,
            'date': transaction.date
        }
        result.append(transaction_data)

    return jsonify(result), 200

@transactions.route('/transactions/<int:id>', methods=['PUT'])
@jwt_required()
def update_transaction(id):
    current_user = get_jwt_identity()
    data = request.get_json()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    transaction = Transaction.query.filter_by(id=id, user_id=user.id).first()

    if not transaction:
        return jsonify({'message': 'Transaction not found'}), 404

    if 'type' in data:
        transaction.type = data['type']
    if 'amount' in data:
        transaction.amount = data['amount']
    if 'description' in data:
        transaction.description = data['description']

    db.session.commit()

    return jsonify({'message': 'Transaction updated successfully'}), 200

@transactions.route('/transactions/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    transaction = Transaction.query.filter_by(id=id, user_id=user.id).first()

    if not transaction:
        return jsonify({'message': 'Transaction not found'}), 404

    db.session.delete(transaction)
    db.session.commit()

    return jsonify({'message': 'Transaction deleted successfully'}), 200

@transactions.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    transactions = Transaction.query.filter_by(user_id=user.id).all()
    
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expenses = sum(t.amount for t in transactions if t.type == 'expense')
    balance = total_income - total_expenses

    # Group transactions by month
    monthly_summary = defaultdict(lambda: {'income': 0, 'expense': 0})

    for transaction in transactions:
        month = transaction.date.strftime('%Y-%m')
        if transaction.type == 'income':
            monthly_summary[month]['income'] += transaction.amount
        else:
            monthly_summary[month]['expense'] += transaction.amount

    monthly_summary = [{'month': month, 'income': data['income'], 'expense': data['expense']} for month, data in monthly_summary.items()]

    return jsonify({
        'total_income': total_income,
        'total_expenses': total_expenses,
        'balance': balance,
        'monthly_summary': monthly_summary
    }), 200

@transactions.route('/report_chart', methods=['GET'])
@jwt_required()
def report_chart():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    transactions = Transaction.query.filter_by(user_id=user.id).all()
    
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expenses = sum(t.amount for t in transactions if t.type == 'expense')
    balance = total_income - total_expenses

    # Group transactions by month
    monthly_summary = defaultdict(lambda: {'income': 0, 'expense': 0})

    for transaction in transactions:
        month = transaction.date.strftime('%Y-%m')
        if transaction.type == 'income':
            monthly_summary[month]['income'] += transaction.amount
        else:
            monthly_summary[month]['expense'] += transaction.amount

    months = sorted(monthly_summary.keys())
    incomes = [monthly_summary[month]['income'] for month in months]
    expenses = [monthly_summary[month]['expense'] for month in months]

    # Plotting
    plt.figure(figsize=(10, 5))
    plt.plot(months, incomes, label='Income', marker='o')
    plt.plot(months, expenses, label='Expense', marker='o')
    plt.xlabel('Month')
    plt.ylabel('Amount')
    plt.title('Monthly Financial Report')
    plt.legend()
    plt.grid(True)

    # Save plot to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()

    return send_file(buf, mimetype='image/png')
