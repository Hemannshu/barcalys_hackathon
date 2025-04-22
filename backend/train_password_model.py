"""
Runner script for training the password strength model.
"""
import os
from password_ml.train import train_model

def main():
    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Setup paths
    rockyou_path = os.path.join(current_dir, 'rockyou.txt')
    model_path = os.path.join(current_dir, 'password_ml', 'models', 'password_strength_model.joblib')
    vis_dir = os.path.join(current_dir, 'password_ml', 'visualizations')
    
    # Train the model
    train_model(
        rockyou_path=rockyou_path,
        model_save_path=model_path,
        vis_dir=vis_dir
    )

if __name__ == "__main__":
    main() 