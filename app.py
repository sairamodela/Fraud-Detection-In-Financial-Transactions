from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import pandas as pd
from datetime import datetime
import os
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.secret_key = '0000' 

# Load dataset
try:
    # Load the dataset
    df = pd.read_csv('data/fraud_data.csv')
    logger.info("Dataset loaded successfully")
    logger.info(f"Number of records: {len(df)}")
    logger.info(f"Number of unique transactions: {df['transaction_id'].nunique()}")
    logger.info(f"Number of unique users: {df['user_id'].nunique()}")
except Exception as e:
    logger.error(f"Error loading dataset: {str(e)}")
    df = pd.DataFrame()  # Empty DataFrame as fallback

# Database initialization
def init_db():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL,
                      email TEXT UNIQUE NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS transaction_history
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id TEXT NOT NULL,
                      transaction_id TEXT NOT NULL,
                      amount REAL NOT NULL,
                      risk_level TEXT NOT NULL,
                      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Modified root route to redirect to login
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            
            if user and check_password_hash(user[2], password):
                session['username'] = username
                logger.info(f"User logged in: {username}")
                # flash('Logged in successfully!')
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Failed login attempt for username: {username}")
                flash('Invalid username or password')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                     (username, hashed_password, email))
            conn.commit()
            conn.close()
            logger.info(f"New user registered: {username}")
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            logger.warning(f"Registration failed - duplicate username/email: {username}")
            flash('Username or email already exists!')
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration')
        
    return render_template('register.html')

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        logger.info(f"User logged out: {username}")
    # flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        now = datetime.now()
        username = session.get('username')
        
        # Get user's transaction history
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        transactions = c.execute('''
            SELECT transaction_id, amount, risk_level, timestamp 
            FROM transaction_history 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 5''', (username,)).fetchall()
        conn.close()
        
        return render_template('index.html', 
                             now=now, 
                             username=username,
                             transactions=transactions)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    """Handle prediction requests"""
    try:
        # Get data from request
        data = {
            'transaction_id': request.form.get('transaction_id'),
            'user_id': request.form.get('user_id'),
            'transaction_date': request.form.get('transactionDate'),
            'amount': float(request.form.get('amount', 0)),
            'merchant_category': request.form.get('merchantCategory'),
            'location': request.form.get('location')
        }

        logger.info(f"Received prediction request: {data}")

        # Validate required fields
        required_fields = ['transaction_id', 'user_id', 'transaction_date', 
                         'amount', 'merchant_category', 'location']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'error': f'Missing required field: {field}'
                }), 400

        # Check if transaction_id and user_id exist in dataset
        valid_transaction = data['transaction_id'] in df['transaction_id'].values
        valid_user = data['user_id'] in df['user_id'].values

        if not valid_transaction or not valid_user:
            fraud_indicators = []
            if not valid_transaction:
                fraud_indicators.append('Invalid Transaction ID')
            if not valid_user:
                fraud_indicators.append('Invalid User ID')

            result = {
                'prediction': 1,
                'probability': 1.0,
                'risk_level': 'High Risk',
                'message': 'Fraudulent transaction detected: Invalid credentials',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'fraud_indicators': fraud_indicators,
                'transaction_details': {
                    'id': data['transaction_id'],
                    'user_id': data['user_id'],
                    'amount': data['amount'],
                    'merchant': data['merchant_category'],
                    'location': data['location'],
                    'validation_status': {
                        'transaction_id': 'Invalid' if not valid_transaction else 'Valid',
                        'user_id': 'Invalid' if not valid_user else 'Valid'
                    }
                }
            }
            
            # Log the fraudulent transaction
            logger.warning(f"Fraudulent transaction detected: {data}")
            
            # Store in transaction history
            try:
                conn = sqlite3.connect('users.db')
                c = conn.cursor()
                c.execute('''INSERT INTO transaction_history 
                            (user_id, transaction_id, amount, risk_level) 
                            VALUES (?, ?, ?, ?)''',
                         (session['username'], data['transaction_id'], 
                          data['amount'], 'High Risk'))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error storing transaction history: {str(e)}")
            
            return jsonify(result)

        # Validate transaction date
        try:
            transaction_date = datetime.strptime(data['transaction_date'], '%Y-%m-%dT%H:%M')
            if transaction_date > datetime.now():
                return jsonify({
                    'error': 'Transaction date cannot be in the future'
                }), 400
        except ValueError as e:
            logger.error(f"Date parsing error: {str(e)}")
            return jsonify({
                'error': 'Invalid date format'
            }), 400

        # Validate amount
        if data['amount'] <= 0:
            return jsonify({
                'error': 'Amount must be greater than 0'
            }), 400

        # Calculate risk score based on rules
        risk_score = 0.0
        fraud_indicators = []

        # Rule 1: High amount
        if data['amount'] > 50000:
            risk_score += 0.4
            fraud_indicators.append('High Transaction Amount')

        # Rule 2: High-risk merchant categories
        high_risk_merchants = ['Electronics', 'Fashion', 'Others']
        if data['merchant_category'] in high_risk_merchants:
            risk_score += 0.3
            fraud_indicators.append('High Risk Merchant Category')

        # Rule 3: Location-based risk
        high_risk_locations = ['Delhi', 'Maharashtra', 'Karnataka']
        if data['location'] in high_risk_locations:
            risk_score += 0.3
            fraud_indicators.append('High Risk Location')

        # Rule 4: Time-based risk (late night transactions)
        hour = transaction_date.hour
        if hour >= 23 or hour <= 4:
            risk_score += 0.2
            fraud_indicators.append('Suspicious Transaction Time')

        # Normalize risk score to be between 0 and 1
        risk_score = min(risk_score, 1.0)
        
        result = {
            'prediction': 1 if risk_score > 0.5 else 0,
            'probability': float(risk_score),
            'risk_level': 'High Risk' if risk_score > 0.5 else 'Low Risk',
            'message': 'Transaction flagged as potentially fraudulent.' if risk_score > 0.5 
                      else 'Transaction appears to be legitimate.',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'fraud_indicators': fraud_indicators,
            'transaction_details': {
                'id': data['transaction_id'],
                'user_id': data['user_id'],
                'amount': data['amount'],
                'merchant': data['merchant_category'],
                'location': data['location'],
                'date': transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
                'validation_status': {
                    'transaction_id': 'Valid',
                    'user_id': 'Valid'
                }
            }
        }

        # Store transaction in history
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('''INSERT INTO transaction_history 
                        (user_id, transaction_id, amount, risk_level) 
                        VALUES (?, ?, ?, ?)''',
                     (session['username'], data['transaction_id'], 
                      data['amount'], result['risk_level']))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error storing transaction history: {str(e)}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({
            'error': f'An error occurred while processing the request: {str(e)}'
        }), 500

@app.route('/profile')
@login_required
def profile():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        user = c.execute('''SELECT username, email, created_at FROM users 
                           WHERE username = ?''', (session['username'],)).fetchone()
        
        # Get transaction statistics
        stats = c.execute('''SELECT 
                            COUNT(*) as total_transactions,
                            SUM(CASE WHEN risk_level = 'High Risk' THEN 1 ELSE 0 END) as high_risk_count,
                            AVG(amount) as avg_amount
                            FROM transaction_history 
                            WHERE user_id = ?''', (session['username'],)).fetchone()
        conn.close()
        
        return render_template('profile.html', user=user, stats=stats)
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return redirect(url_for('dashboard'))


@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    logger.info("Starting Flask application...")
    # logger.info("Access the application at: http://127.0.0.1:5000")
    import webbrowser
    # webbrowser.open('http://127.0.0.1:5000/login')
    app.run(debug=True, port=5000)