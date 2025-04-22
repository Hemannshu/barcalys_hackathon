import os
from data_processor import PasswordDataProcessor
from model import PasswordStrengthModel
from visualizations import ModelVisualizer
import argparse

def train_model(rockyou_path, model_save_path, vis_dir='visualizations'):
    """Train the password strength model and generate visualizations."""
    
    # Create directories if they don't exist
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    os.makedirs(vis_dir, exist_ok=True)
    
    # Initialize data processor
    processor = PasswordDataProcessor(rockyou_path)
    
    # Prepare dataset
    print("Preparing dataset...")
    df = processor.prepare_training_data()
    
    # Split dataset
    print("Splitting dataset...")
    (X_train, y_train), (X_val, y_val), (X_test, y_test) = processor.split_dataset(df)
    
    # Initialize and train model
    print("Initializing model...")
    model = PasswordStrengthModel()
    
    print("Training model...")
    model.train(X_train, y_train, X_val, y_val)
    
    # Evaluate on test set
    print("Evaluating model...")
    test_predictions = model.predict(X_test)
    test_score = model.models['gbm'].score(
        model.scaler.transform(X_test), 
        y_test
    )
    print(f"Test set R² score: {test_score:.4f}")
    
    # Generate visualizations
    print("Generating visualizations...")
    visualizer = ModelVisualizer(save_dir=vis_dir)
    
    # Plot feature importance
    feature_names = list(X_train.columns)
    visualizer.plot_feature_importance(
        model.models['gbm'], 
        feature_names,
        "Password Feature Importance (GBM)"
    )
    
    # Plot strength distribution
    visualizer.plot_strength_distribution(
        y_test, 
        test_predictions,
        "Password Strength Distribution (Test Set)"
    )
    
    # Plot confusion matrix
    visualizer.plot_confusion_matrix(
        y_test, 
        test_predictions,
        "Password Strength Category Confusion Matrix"
    )
    
    # Plot error analysis for key features
    key_features = ['length', 'entropy', 'char_types', 'repeating_chars']
    for feature in key_features:
        if feature in X_test.columns:
            visualizer.plot_error_analysis(
                y_test,
                test_predictions,
                X_test[feature],
                feature.replace('_', ' ').title()
            )
    
    # Compare models
    print("Comparing models...")
    X_test_scaled = model.scaler.transform(X_test)
    model_predictions = {
        'GBM': model.models['gbm'].predict(X_test_scaled),
        'Random Forest': model.models['rf'].predict(X_test_scaled),
        'Neural Network': model.models['nn'].predict(X_test_scaled)
    }
    visualizer.plot_model_comparison(model_predictions, y_test)
    
    # Save model
    print("Saving model...")
    model.save_model(model_save_path)
    
    print("Training and visualization complete!")
    print(f"Model saved to: {model_save_path}")
    print(f"Visualizations saved to: {vis_dir}")

def main():
    parser = argparse.ArgumentParser(description='Train password strength model')
    parser.add_argument(
        '--rockyou-path',
        required=True,
        help='Path to the RockYou dataset'
    )
    parser.add_argument(
        '--model-path',
        default='models/password_strength_model.joblib',
        help='Path to save the trained model'
    )
    parser.add_argument(
        '--vis-dir',
        default='visualizations',
        help='Directory to save visualizations'
    )
    
    args = parser.parse_args()
    train_model(args.rockyou_path, args.model_path, args.vis_dir)

if __name__ == "__main__":
    main() 