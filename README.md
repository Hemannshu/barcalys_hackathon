# Password Strength Analyzer and Manager

A comprehensive password security solution that combines advanced machine learning, cryptographic analysis, and real-time vulnerability assessment to help users create and manage secure passwords.

## 🌟 Features

### 1. Advanced Password Analysis
- **ML-Based Strength Assessment**: Uses ensemble machine learning models (Gradient Boosting, Random Forest, Neural Networks) to evaluate password strength
- **Pattern Detection**: Identifies common patterns, keyboard sequences, and vulnerable combinations
- **Entropy Calculation**: Measures password randomness and complexity
- **Real-time Strength Meter**: Visual feedback on password strength with detailed metrics
- **Attack Simulation**: Estimates crack times for different attack methods:
  - Brute Force
  - Dictionary Attacks
  - Pattern-based Attacks
  - Targeted Attacks

### 2. Password Health Dashboard
- **Password Portfolio Analysis**: Overview of all stored passwords
- **Health Metrics**: Average strength score, compromised password detection
- **Vulnerability Assessment**: Detailed analysis of potential security risks
- **Improvement Suggestions**: Actionable recommendations for stronger passwords

### 3. Face Authentication
- **Biometric Security**: Additional layer of security using facial recognition
- **FaceIO Integration**: Secure and privacy-focused face authentication
- **Multi-factor Authentication**: Combines password and biometric verification

### 4. Hash Analysis
- **Multiple Hash Algorithms**: Support for:
  - MD5
  - SHA-1
  - SHA-256
  - SHA3-256
- **Hash Generation**: Create and analyze password hashes
- **Vulnerability Assessment**: Evaluate hash strength and potential risks

### 5. Browser Extension
- **Password Manager Integration**: Easy access to stored passwords
- **Real-time Strength Analysis**: Instant feedback while creating passwords
- **Auto-fill Capability**: Secure and convenient password entry

## 🛠️ Technology Stack

### Frontend
- **React 18.2.0**: Modern UI framework
- **React Router DOM 7.5.1**: Client-side routing
- **Chart.js**: Data visualization
- **CryptoJS**: Client-side cryptographic operations
- **React Force Graph**: Network visualization
- **A-Frame**: WebVR framework for 3D visualization

### Backend
- **Express 5.1.0**: Web application framework
- **MySQL2 3.14.0**: Database management
- **Firebase/Firebase Admin**: Authentication and cloud services
- **bcrypt 5.1.1**: Password hashing
- **HIBP 15.0.1**: Have I Been Pwned integration

### Machine Learning
- **Ensemble Models**:
  - Gradient Boosting Regressor
  - Random Forest Regressor
  - Neural Network (MLP)
- **scikit-learn**: ML model training and evaluation
- **numpy**: Numerical computations
- **pandas**: Data processing

## 🚀 Getting Started

### Prerequisites
- Node.js (v14 or higher)
- Python 3.8+
- MySQL Database
- Firebase Account

### Installation

1. Clone the repository:
\`\`\`bash
git clone [repository-url]
\`\`\`

2. Install frontend dependencies:
\`\`\`bash
cd barcalys_hackathon/frontend
npm install
\`\`\`

3. Install backend dependencies:
\`\`\`bash
cd ../backend
pip install -r requirements.txt
\`\`\`

4. Set up environment variables:
\`\`\`bash
# Frontend (.env)
REACT_APP_API_URL=http://localhost:5000
REACT_APP_FIREBASE_CONFIG=your_firebase_config

# Backend (.env)
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
FIREBASE_ADMIN_CONFIG=your_firebase_admin_config
\`\`\`

5. Start the application:
\`\`\`bash
# Start backend
python app.py

# Start frontend (in a new terminal)
cd ../frontend
npm start
\`\`\`

## 🔒 Security Features

### Password Analysis
- Entropy calculation based on character set complexity
- Pattern detection for common vulnerabilities
- Real-time strength assessment
- Crack time estimation for various attack methods

### ML Model Features
- Password length
- Character type diversity
- Special character usage
- Pattern recognition
- Common sequence detection
- Repetition analysis

### Attack Simulations
- Brute force scenarios
- Dictionary attack vulnerability
- Pattern-based attack risk
- Social engineering susceptibility

## 📊 Data Visualization

- Strength meter with color-coded feedback
- Radar charts for vulnerability analysis
- Character composition breakdown
- Attack risk assessment graphs
- Password health portfolio visualization

## 🤖 Machine Learning Implementation

### Model Architecture
- **Ensemble Approach**: Combines multiple models for robust predictions
- **Feature Engineering**: Extracts relevant password characteristics
- **Real-time Analysis**: Quick strength assessment and recommendations

### Training Data
- Large password dataset with various strength levels
- Pattern analysis from common password breaches
- Character distribution statistics

## 🔐 Best Practices

- No plaintext password storage
- Secure hash generation and comparison
- Rate limiting for protection against brute force
- Secure session management
- Input sanitization and validation

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

For any queries or support, please contact [contact information] 
