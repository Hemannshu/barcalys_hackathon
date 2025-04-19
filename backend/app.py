from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS

# Health check endpoint
@app.route('/')
def home():
    return jsonify({"status": "running", "message": "Password Analyzer API"})

# Analysis endpoint
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    
    # Your actual analysis logic here
    result = {
        "strength": 85,
        "crack_time": "3 years",
        "suggestions": ["5uMM3r#2024*Q"]
    }
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5000, debug=True)