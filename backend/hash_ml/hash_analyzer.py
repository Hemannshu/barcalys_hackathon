import numpy as np
from typing import Dict, Any, List
import hashlib
import os
from sklearn.preprocessing import StandardScaler
import joblib

class HashVulnerabilityAnalyzer:
    def __init__(self, model_path: str = None):
        """Initialize the hash vulnerability analyzer."""
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.model = None
        self.hash_families = {
            'md5': {'bits': 128, 'quantum_resistant': False, 'collision_found': True},
            'sha1': {'bits': 160, 'quantum_resistant': False, 'collision_found': True},
            'sha256': {'bits': 256, 'quantum_resistant': False, 'collision_found': False},
            'sha3_256': {'bits': 256, 'quantum_resistant': True, 'collision_found': False},
            'blake2b': {'bits': 512, 'quantum_resistant': True, 'collision_found': False}
        }
        
        if model_path and os.path.exists(model_path):
            try:
                self._load_model(model_path)
            except Exception as e:
                print(f"Error loading model: {str(e)}")

    def _load_model(self, path: str) -> None:
        """Load the trained model from disk."""
        model_data = joblib.load(path)
        self.model = model_data.get('model')
        self.scaler = model_data.get('scaler')

    def _save_model(self, path: str) -> None:
        """Save the trained model to disk."""
        model_data = {
            'model': self.model,
            'scaler': self.scaler
        }
        joblib.dump(model_data, path)

    def _extract_features(self, hash_value: str, algorithm: str) -> np.ndarray:
        """Extract features from a hash value and its algorithm."""
        # Basic features
        features = {
            'length': len(hash_value),
            'unique_chars': len(set(hash_value)),
            'hex_chars': sum(1 for c in hash_value if c in '0123456789abcdef'),
            'bit_length': len(hash_value) * 4,  # hex to bits
            'algorithm_bits': self.hash_families.get(algorithm, {}).get('bits', 0),
            'quantum_resistant': int(self.hash_families.get(algorithm, {}).get('quantum_resistant', False)),
            'known_collisions': int(self.hash_families.get(algorithm, {}).get('collision_found', False))
        }
        
        # Bit distribution analysis
        bit_counts = self._analyze_bit_distribution(hash_value)
        features.update(bit_counts)
        
        # Convert to numpy array
        return np.array(list(features.values()))

    def _analyze_bit_distribution(self, hash_value: str) -> Dict[str, float]:
        """Analyze the distribution of bits in the hash value."""
        # Convert hex to binary
        binary = bin(int(hash_value, 16))[2:].zfill(len(hash_value) * 4)
        
        # Calculate bit statistics
        ones_count = binary.count('1')
        zeros_count = binary.count('0')
        
        return {
            'ones_ratio': ones_count / len(binary),
            'zeros_ratio': zeros_count / len(binary),
            'bit_balance': abs(0.5 - (ones_count / len(binary)))
        }

    def analyze_hash(self, hash_value: str, algorithm: str) -> Dict[str, Any]:
        """Analyze a hash value for vulnerabilities."""
        try:
            # Extract features
            features = self._extract_features(hash_value, algorithm)
            
            # If model is available, use it for prediction
            if self.model:
                scaled_features = self.scaler.transform(features.reshape(1, -1))
                vulnerability_score = float(self.model.predict(scaled_features)[0])
                confidence = float(self.model.predict_proba(scaled_features).max())
            else:
                # Fallback to heuristic analysis
                vulnerability_score = self._heuristic_analysis(hash_value, algorithm)
                confidence = 0.7  # Default confidence for heuristic analysis
            
            # Generate comprehensive analysis
            analysis = {
                'vulnerability_score': vulnerability_score,
                'confidence': confidence,
                'algorithm_details': {
                    'name': algorithm,
                    'bit_length': self.hash_families.get(algorithm, {}).get('bits', 0),
                    'quantum_resistant': self.hash_families.get(algorithm, {}).get('quantum_resistant', False)
                },
                'risk_factors': self._assess_risk_factors(algorithm),
                'recommendations': self._generate_recommendations(algorithm, vulnerability_score)
            }
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing hash: {str(e)}")
            return {
                'error': True,
                'message': f'Failed to analyze hash: {str(e)}'
            }

    def _heuristic_analysis(self, hash_value: str, algorithm: str) -> float:
        """Perform heuristic-based vulnerability analysis when model is not available."""
        base_score = 0.0
        
        # Algorithm-based scoring
        if algorithm == 'md5':
            base_score += 0.8  # Known to be vulnerable
        elif algorithm == 'sha1':
            base_score += 0.6  # Known collisions
        elif algorithm == 'sha256':
            base_score += 0.2  # Currently secure
        elif algorithm == 'sha3_256':
            base_score += 0.1  # Very secure
        
        # Bit distribution analysis
        bit_stats = self._analyze_bit_distribution(hash_value)
        if abs(bit_stats['bit_balance']) > 0.1:
            base_score += 0.1
        
        return min(1.0, base_score)

    def _assess_risk_factors(self, algorithm: str) -> List[Dict[str, str]]:
        """Assess specific risk factors for the hash algorithm."""
        risks = []
        
        if algorithm == 'md5':
            risks.extend([
                {'type': 'collision', 'severity': 'high', 'description': 'Known collision vulnerabilities exist'},
                {'type': 'quantum', 'severity': 'high', 'description': 'Vulnerable to quantum attacks'}
            ])
        elif algorithm == 'sha1':
            risks.extend([
                {'type': 'collision', 'severity': 'medium', 'description': 'Theoretical collision attacks possible'},
                {'type': 'quantum', 'severity': 'high', 'description': 'Vulnerable to quantum attacks'}
            ])
        elif algorithm == 'sha256':
            risks.extend([
                {'type': 'quantum', 'severity': 'medium', 'description': 'Potentially vulnerable to future quantum attacks'}
            ])
        
        return risks

    def _generate_recommendations(self, algorithm: str, vulnerability_score: float) -> List[str]:
        """Generate recommendations based on the analysis."""
        recommendations = []
        
        if vulnerability_score > 0.7:
            recommendations.append(f"Immediately replace {algorithm} with a more secure alternative")
            recommendations.append("Consider using SHA-3 or BLAKE2b for better security")
        elif vulnerability_score > 0.4:
            recommendations.append(f"Plan to upgrade from {algorithm} in the near future")
            recommendations.append("Monitor for new vulnerabilities and attack vectors")
        
        if not self.hash_families.get(algorithm, {}).get('quantum_resistant', False):
            recommendations.append("Consider quantum-resistant alternatives for long-term security")
        
        return recommendations

    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train the vulnerability analysis model."""
        # Implementation for model training
        pass 