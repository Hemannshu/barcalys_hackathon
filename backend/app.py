from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import jwt
import datetime
from functools import wraps
from password_ml import MLPasswordAnalyzer

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
        analysis = password_analyzer.analyze_password(password)

        if not analysis:
            return jsonify({
                'error': True,
                'message': 'Failed to analyze password'
            }), 500

        # Transform crack times into a more UI-friendly format
        formatted_crack_times = {}
        for method, time_data in analysis.get('crack_times', {}).items():
            formatted_name = ' '.join(word.capitalize() for word in method.split('_'))
            formatted_crack_times[formatted_name] = {
                'time_readable': time_data.get('time_readable', 'unknown'),
                'description': time_data.get('description', ''),
                'seconds': time_data.get('seconds', 0)
            }

        # Transform analysis into expected format
        response = {
            'strength_score': analysis.get('strength_score', 0) * 10,  # Convert 0-10 to 0-100
            'category': analysis.get('category', 'Unknown'),
            'confidence': analysis.get('confidence', 0),
            'features': {
                'length': len(password),
                'entropy': analysis.get('features', {}).get('entropy', 0),
                'has_upper': analysis.get('features', {}).get('has_upper', False),
                'has_lower': analysis.get('features', {}).get('has_lower', False),
                'has_digit': analysis.get('features', {}).get('has_digit', False),
                'has_special': analysis.get('features', {}).get('has_special', False),
                'char_types': analysis.get('features', {}).get('char_types', 0)
            },
            'crack_times': formatted_crack_times,
            'suggestions': analysis.get('suggestions', [])
        }

        return jsonify(response), 200

    except Exception as e:
        app.logger.error(f"Error analyzing password: {str(e)}")
        return jsonify({
            'error': True,
            'message': f'Internal server error: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)