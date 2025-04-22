from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import jwt
import datetime
from functools import wraps
from password_ml import MLPasswordAnalyzer
from hash_ml.hash_analyzer import HashVulnerabilityAnalyzer

app = Flask(__name__, static_folder='../frontend/build')
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(days=1)

# Initialize password analyzer with trained model
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, 'password_ml', 'models', 'password_strength_model.joblib')

# Create models directory if it doesn't exist
os.makedirs(os.path.dirname(model_path), exist_ok=True)

try:
    password_analyzer = MLPasswordAnalyzer(model_path=model_path)
except Exception as e:
    print(f"Error initializing password analyzer: {str(e)}")
    # Initialize with default settings if model loading fails
    password_analyzer = MLPasswordAnalyzer()

# Initialize hash analyzer
hash_analyzer = HashVulnerabilityAnalyzer()

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
@app.route('/api/analyze-password', methods=['POST'])
def analyze_password():
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({
                'error': True,
                'message': 'No password provided'
            }), 400

        password = data['password']
        
        # Initialize the standard password analyzer
        from password_analyzer import PasswordAnalyzer
        standard_analyzer = PasswordAnalyzer()
        standard_analysis = standard_analyzer.analyze_password(password)
        
        # Get ML analysis if available
        ml_analysis = password_analyzer.analyze_password(password)

        # Combine both analyses
        response = {
            'score': min(1.0, max(0.0, standard_analysis['score'] / 100.0)),  # Normalize score to 0-1 range
            'category': standard_analysis['category'],
            'entropy': standard_analysis['entropy'],
            'patterns': standard_analysis['patterns'],
            'suggestions': standard_analysis['suggestions'],
            'features': {
                'length': len(password),
                'entropy': standard_analysis['entropy'],
                'has_upper': any(c.isupper() for c in password),
                'has_lower': any(c.islower() for c in password),
                'has_digit': any(c.isdigit() for c in password),
                'has_special': any(not c.isalnum() for c in password),
                'char_types': (
                    (1 if any(c.isupper() for c in password) else 0) +
                    (1 if any(c.islower() for c in password) else 0) +
                    (1 if any(c.isdigit() for c in password) else 0) +
                    (1 if any(not c.isalnum() for c in password) else 0)
                )
            }
        }

        # Process crack times to handle Infinity values
        crack_times = standard_analysis.get('crack_times', {})
        processed_crack_times = {}
        
        for method, data in crack_times.items():
            if not isinstance(data, dict):
                continue
                
            processed_data = data.copy()
            if 'seconds' in processed_data:
                if processed_data['seconds'] == float('inf'):
                    processed_data['seconds'] = 1e100  # Use a very large number instead of Infinity
                    processed_data['time_readable'] = 'centuries'
                elif processed_data['seconds'] == float('-inf'):
                    processed_data['seconds'] = 0
                    processed_data['time_readable'] = 'instant'
            
            processed_crack_times[method] = processed_data
        
        response['crack_times'] = processed_crack_times

        # Add ML confidence if available
        if ml_analysis and isinstance(ml_analysis, dict):
            response['confidence'] = ml_analysis.get('confidence', 0.7)  # Default to 0.7 if not available
            app.logger.info(f"ML confidence: {response['confidence']}")  # Add debug logging

        app.logger.info(f"Final response: {response}")  # Add debug logging
        return jsonify(response), 200

    except Exception as e:
        app.logger.error(f"Error analyzing password: {str(e)}")
        return jsonify({
            'error': True,
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/analyze-hash', methods=['POST'])
@token_required
def analyze_hash(current_user):
    """Analyze a cryptographic hash for vulnerabilities."""
    try:
        data = request.get_json()
        if not data or 'hash' not in data or 'algorithm' not in data:
            return jsonify({
                'error': True,
                'message': 'Missing hash value or algorithm'
            }), 400

        hash_value = data['hash']
        algorithm = data['algorithm'].lower()

        # Validate hash format
        if not all(c in '0123456789abcdefABCDEF' for c in hash_value):
            return jsonify({
                'error': True,
                'message': 'Invalid hash format - must be hexadecimal'
            }), 400

        # Analyze hash
        analysis = hash_analyzer.analyze_hash(hash_value, algorithm)
        
        if 'error' in analysis:
            return jsonify(analysis), 500

        return jsonify(analysis), 200

    except Exception as e:
        app.logger.error(f"Error analyzing hash: {str(e)}")
        return jsonify({
            'error': True,
            'message': f'Internal server error: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)