from .data_processor import PasswordDataProcessor
from .model import PasswordStrengthModel
import numpy as np
import os

class MLPasswordAnalyzer:
    def __init__(self, model_path=None):
        """Initialize the ML-based password analyzer."""
        self.processor = PasswordDataProcessor(rockyou_path=None)  # We don't need the dataset for inference
        
        # Try to load the model, fall back to basic analysis if model not available
        self.model = None
        if model_path and os.path.exists(model_path):
            try:
                self.model = PasswordStrengthModel(model_path)
            except Exception as e:
                print(f"Error loading model: {str(e)}")
        
        self.feature_order = [
            'length', 'uppercase_count', 'lowercase_count', 'digit_count',
            'special_char_count', 'has_alpha', 'has_digit', 'has_special',
            'has_uppercase', 'has_lowercase'
        ]
    
    def analyze_password(self, password):
        """Analyze a password using the ML model or basic analysis if model not available."""
        try:
            # Extract features
            features = self.processor._extract_features(password)
            
            # Calculate additional metrics
            entropy = self.processor._calculate_entropy(password)
            char_types = sum([
                features['has_uppercase'],
                features['has_lowercase'],
                features['has_digit'],
                features['has_special']
            ])
            repeating_chars = len(set(c for c in password if password.count(c) > 1))
            
            # Convert features to array format
            feature_array = np.array([features[key] for key in self.feature_order])
            
            # Get analysis (either from model or basic)
            if self.model:
                analysis = self.model.analyze_password(feature_array)
                strength_score = float(analysis['strength_score'])
                category = analysis['category']
                confidence = analysis['confidence'] / 100.0
            else:
                # Basic analysis without ML model
                basic_score = self._calculate_basic_score(features, entropy)
                strength_score = basic_score
                category = self._get_category(basic_score)
                confidence = 0.7  # Lower confidence for basic analysis
            
            # Calculate crack times based on entropy
            crack_times = self._estimate_crack_times(entropy)
            
            # Enhance the analysis with additional information
            enhanced_analysis = {
                'strength_score': strength_score,
                'category': category,
                'confidence': confidence,
                'features': {
                    'length': features['length'],
                    'entropy': entropy,
                    'char_types': char_types,
                    'has_upper': bool(features['has_uppercase']),
                    'has_lower': bool(features['has_lowercase']),
                    'has_digit': bool(features['has_digit']),
                    'has_special': bool(features['has_special']),
                    'repeating_chars': repeating_chars
                },
                'crack_times': crack_times,
                'suggestions': self._generate_suggestions(features, {'strength_score': strength_score * 100}, entropy)
            }
            
            return enhanced_analysis
            
        except Exception as e:
            print(f"Error analyzing password: {str(e)}")
            return {
                'error': 'Failed to analyze password',
                'details': str(e)
            }
    
    def _calculate_basic_score(self, features, entropy):
        """Calculate a basic password strength score without ML model."""
        # Base score from length (0-4)
        length_score = min(4, features['length'] / 8)
        
        # Character type score (0-4)
        char_type_score = sum([
            features['has_uppercase'],
            features['has_lowercase'],
            features['has_digit'],
            features['has_special']
        ])
        
        # Entropy score (0-2)
        entropy_score = min(2, entropy / 50)
        
        # Final score (0-10)
        total_score = length_score + char_type_score + entropy_score
        return min(10, total_score)
    
    def _get_category(self, score):
        """Get password category based on score."""
        if score >= 8:
            return "Very Strong"
        elif score >= 6:
            return "Strong"
        elif score >= 4:
            return "Moderate"
        elif score >= 2:
            return "Weak"
        return "Very Weak"
    
    def _estimate_crack_times(self, entropy):
        """Estimate crack times based on entropy and different attack types."""
        # Guesses needed = 2^entropy
        guesses = 2 ** entropy
        
        # Attack speeds for different methods (guesses per second)
        speeds = {
            'brute_force': {
                'speed': 1e9,  # 1 billion/sec (GPU)
                'description': 'Tries every possible combination'
            },
            'dictionary': {
                'speed': 1e7,  # 10 million/sec
                'description': 'Uses common password lists'
            },
            'pattern_based': {
                'speed': 1e8,  # 100 million/sec
                'description': 'Targets common patterns and variations'
            },
            'targeted': {
                'speed': 1e5,  # 100,000/sec
                'description': 'Focused attack using personal info'
            }
        }
        
        crack_times = {}
        for method, info in speeds.items():
            seconds = guesses / info['speed']
            crack_times[method] = {
                'seconds': seconds,
                'time_readable': self._format_time(seconds),
                'description': info['description']
            }
        
        return crack_times
    
    def _format_time(self, seconds):
        """Format time in seconds to human-readable string."""
        if seconds < 1:
            return "instantly"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        if seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        if seconds < 31536000*100:
            return f"{seconds/31536000:.1f} years"
        return "centuries"
    
    def _generate_suggestions(self, features, analysis, entropy):
        """Generate improvement suggestions based on features and analysis."""
        suggestions = []
        
        if features['length'] < 12:
            suggestions.append("Increase password length to at least 12 characters")
        
        if not features['has_uppercase']:
            suggestions.append("Add uppercase letters")
        
        if not features['has_lowercase']:
            suggestions.append("Add lowercase letters")
        
        if not features['has_digit']:
            suggestions.append("Add numbers")
        
        if not features['has_special']:
            suggestions.append("Add special characters")
        
        if entropy < 50:
            suggestions.append("Increase password complexity for better security")
        
        if analysis['strength_score'] < 60:
            suggestions.append("Consider using a password manager to generate stronger passwords")
        
        return suggestions

# Usage example:
if __name__ == "__main__":
    analyzer = MLPasswordAnalyzer()
    result = analyzer.analyze_password("MyPassword123!")
    print(result) 