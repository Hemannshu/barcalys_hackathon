import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report
import os

class ModelVisualizer:
    def __init__(self, save_dir='visualizations'):
        """Initialize the visualizer with a directory to save plots."""
        self.save_dir = save_dir
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
        
        # Set style
        plt.style.use('seaborn')
        sns.set_palette("husl")
    
    def plot_feature_importance(self, model, feature_names, title="Feature Importance"):
        """Plot feature importance for tree-based models."""
        plt.figure(figsize=(12, 6))
        
        # Get feature importance (works for GBM and RF)
        importance = model.feature_importances_
        
        # Sort features by importance
        indices = np.argsort(importance)[::-1]
        
        # Plot
        plt.title(title)
        plt.bar(range(len(importance)), importance[indices])
        plt.xticks(range(len(importance)), [feature_names[i] for i in indices], rotation=45, ha='right')
        plt.tight_layout()
        
        # Save
        plt.savefig(os.path.join(self.save_dir, 'feature_importance.png'))
        plt.close()
    
    def plot_strength_distribution(self, y_true, y_pred, title="Password Strength Distribution"):
        """Plot the distribution of true vs predicted password strengths."""
        plt.figure(figsize=(10, 6))
        
        sns.kdeplot(data=y_true, label='True Strength', alpha=0.6)
        sns.kdeplot(data=y_pred, label='Predicted Strength', alpha=0.6)
        
        plt.title(title)
        plt.xlabel('Strength Score')
        plt.ylabel('Density')
        plt.legend()
        plt.tight_layout()
        
        plt.savefig(os.path.join(self.save_dir, 'strength_distribution.png'))
        plt.close()
    
    def plot_confusion_matrix(self, y_true, y_pred, title="Strength Category Confusion Matrix"):
        """Plot confusion matrix for strength categories."""
        # Convert continuous scores to categories
        def score_to_category(score):
            if score < 20: return "Very Weak"
            elif score < 40: return "Weak"
            elif score < 60: return "Moderate"
            elif score < 80: return "Strong"
            else: return "Very Strong"
        
        y_true_cat = [score_to_category(s) for s in y_true]
        y_pred_cat = [score_to_category(s) for s in y_pred]
        
        # Create confusion matrix
        categories = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        cm = confusion_matrix(y_true_cat, y_pred_cat, labels=categories)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=categories, yticklabels=categories)
        
        plt.title(title)
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.tight_layout()
        
        plt.savefig(os.path.join(self.save_dir, 'confusion_matrix.png'))
        plt.close()
    
    def plot_error_analysis(self, y_true, y_pred, features, feature_name):
        """Plot error analysis for a specific feature."""
        errors = np.abs(y_true - y_pred)
        
        plt.figure(figsize=(10, 6))
        plt.scatter(features, errors, alpha=0.5)
        plt.xlabel(feature_name)
        plt.ylabel('Absolute Error')
        plt.title(f'Error Analysis by {feature_name}')
        
        # Add trend line
        z = np.polyfit(features, errors, 1)
        p = np.poly1d(z)
        plt.plot(features, p(features), "r--", alpha=0.8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.save_dir, f'error_analysis_{feature_name}.png'))
        plt.close()
    
    def plot_model_comparison(self, predictions_dict, y_true):
        """Compare predictions from different models."""
        plt.figure(figsize=(12, 6))
        
        for model_name, preds in predictions_dict.items():
            errors = np.abs(y_true - preds)
            sns.kdeplot(data=errors, label=model_name, alpha=0.6)
        
        plt.title('Model Error Distribution Comparison')
        plt.xlabel('Absolute Error')
        plt.ylabel('Density')
        plt.legend()
        plt.tight_layout()
        
        plt.savefig(os.path.join(self.save_dir, 'model_comparison.png'))
        plt.close()

# Usage example in train.py:
"""
from visualizations import ModelVisualizer

# After training:
visualizer = ModelVisualizer()

# Plot feature importance
feature_names = list(X_train.columns)
visualizer.plot_feature_importance(model.models['gbm'], feature_names)

# Plot strength distribution
visualizer.plot_strength_distribution(y_test, test_predictions)

# Plot confusion matrix
visualizer.plot_confusion_matrix(y_test, test_predictions)

# Plot error analysis for specific features
visualizer.plot_error_analysis(y_test, test_predictions, X_test['length'], 'Password Length')

# Compare models
model_predictions = {
    'GBM': model.models['gbm'].predict(X_test_scaled),
    'RF': model.models['rf'].predict(X_test_scaled),
    'NN': model.models['nn'].predict(X_test_scaled)
}
visualizer.plot_model_comparison(model_predictions, y_test)
""" 