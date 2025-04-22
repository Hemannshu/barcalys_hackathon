import numpy as np
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
import joblib
import os

class PasswordStrengthModel:
    def __init__(self, model_path=None):
        self.scaler = StandardScaler()
        self.models = {
            'gbm': GradientBoostingRegressor(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            ),
            'rf': RandomForestRegressor(
                n_estimators=200,
                max_depth=10,
                random_state=42
            ),
            'nn': MLPRegressor(
                hidden_layer_sizes=(100, 50),
                max_iter=1000,
                random_state=42
            )
        }
        self.model_weights = {'gbm': 0.4, 'rf': 0.4, 'nn': 0.2}
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def train(self, X_train, y_train, X_val, y_val):
        """Train all models in the ensemble."""
        print("Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_train_scaled, y_train)
            val_score = model.score(X_val_scaled, y_val)
            print(f"{name} validation R² score: {val_score:.4f}")
    
    def predict(self, X):
        """Make ensemble predictions."""
        X_scaled = self.scaler.transform(X)
        predictions = {}
        
        for name, model in self.models.items():
            predictions[name] = model.predict(X_scaled)
        
        # Weighted average of predictions
        final_prediction = np.zeros_like(predictions['gbm'])
        for name, pred in predictions.items():
            final_prediction += pred * self.model_weights[name]
        
        return np.clip(final_prediction, 0, 100)
    
    def save_model(self, path):
        """Save the ensemble model and scaler."""
        model_data = {
            'scaler': self.scaler,
            'models': self.models,
            'weights': self.model_weights
        }
        joblib.dump(model_data, path)
        print(f"Model saved to {path}")
    
    def load_model(self, path):
        """Load the ensemble model and scaler."""
        model_data = joblib.load(path)
        self.scaler = model_data['scaler']
        self.models = model_data['models']
        self.model_weights = model_data['weights']
        print(f"Model loaded from {path}")
    
    def analyze_password(self, features):
        """Analyze a single password using the ensemble model."""
        prediction = self.predict(features.reshape(1, -1))[0]
        
        strength_categories = {
            (0, 20): "Very Weak",
            (20, 40): "Weak",
            (40, 60): "Moderate",
            (60, 80): "Strong",
            (80, 100): "Very Strong"
        }
        
        # Determine strength category
        category = next(
            label for (min_score, max_score), label 
            in strength_categories.items() 
            if min_score <= prediction < max_score
        )
        
        return {
            'strength_score': prediction,
            'category': category,
            'confidence': self._calculate_confidence(features)
        }
    
    def _calculate_confidence(self, features):
        """Calculate prediction confidence based on model agreement."""
        X_scaled = self.scaler.transform(features.reshape(1, -1))
        predictions = [
            model.predict(X_scaled)[0] 
            for model in self.models.values()
        ]
        
        # Calculate standard deviation of predictions
        std = np.std(predictions)
        # Convert to confidence score (inverse relationship)
        confidence = max(0, min(100, 100 - (std * 10)))
        
        return confidence 