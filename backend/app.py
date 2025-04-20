from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import jwt
import datetime
from functools import wraps
from password_analyzer import PasswordAnalyzer

app = Flask(__name__, static_folder='../frontend/build')
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(days=1)

# Initialize password analyzer
password_analyzer = PasswordAnalyzer()

# Mock user database (replace with actual database in production)
users = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.get(data['email'])
            if not current_user:
                return jsonify({'message': 'Invalid token'}), 401
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

# Authentication endpoints
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('full_name'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    if data['email'] in users:
        return jsonify({'message': 'Email already registered'}), 400
    
    users[data['email']] = {
        'email': data['email'],
        'password': data['password'],  # In production, hash the password
        'full_name': data['full_name']
    }
    
    token = jwt.encode({
        'email': data['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'token': token,
        'user': {
            'email': data['email'],
            'full_name': data['full_name']
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    user = users.get(data['email'])
    if not user or user['password'] != data['password']:  # In production, verify hashed password
        return jsonify({'message': 'Invalid email or password'}), 401
    
    token = jwt.encode({
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'token': token,
        'user': {
            'email': user['email'],
            'full_name': user['full_name']
        }
    })

# Password analysis endpoint
@app.route('/api/analyze', methods=['POST'])
@token_required
def analyze_password(current_user):
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Use our password analyzer to analyze the password
    result = password_analyzer.analyze_password(password)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)