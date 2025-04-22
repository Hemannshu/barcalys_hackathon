import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from collections import Counter
import re
from tqdm import tqdm
import gc

class PasswordDataProcessor:
    def __init__(self, rockyou_path):
        self.rockyou_path = rockyou_path
        self.max_passwords = 1_000_000  # Limit total passwords processed
        self.chunk_size = 100_000  # Process in chunks of 100k passwords
        self.char_vocab = set()
        self.pattern_features = [
            r'\d+',                    # numbers
            r'[A-Z]+',                 # uppercase
            r'[a-z]+',                 # lowercase
            r'[^A-Za-z0-9]+',          # special chars
            r'(.)\1+',                 # repeating chars
            r'(abc|123|qwerty|admin)', # common patterns
        ]
    
    def password_generator(self):
        """Generator to yield valid passwords from the dataset."""
        count = 0
        with open(self.rockyou_path, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if self._is_valid_password(password):
                    self.char_vocab.update(password)
                    yield password
                    count += 1
                    if count >= self.max_passwords:
                        break

    def _is_valid_password(self, password):
        """Check if password meets basic criteria."""
        if not password:
            return False
        if len(password) < 6 or len(password) > 50:
            return False
        if not all(ord(c) < 128 for c in password):  # ASCII only
            return False
        return True

    def _extract_features(self, password):
        """Extract features from a single password."""
        features = {
            'length': len(password),
            'uppercase_count': sum(1 for c in password if c.isupper()),
            'lowercase_count': sum(1 for c in password if c.islower()),
            'digit_count': sum(1 for c in password if c.isdigit()),
            'special_char_count': sum(1 for c in password if not c.isalnum()),
            'has_alpha': any(c.isalpha() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
        }
        return features

    def process_chunk(self, passwords):
        """Process a chunk of passwords and extract features."""
        features_list = []
        for password in passwords:
            features = self._extract_features(password)
            features_list.append(features)
        return pd.DataFrame(features_list)

    def prepare_training_data(self):
        """Prepare training data in chunks to manage memory usage."""
        print("Processing passwords in chunks...")
        all_features = []
        passwords_processed = 0
        
        # Create a buffer for the current chunk
        current_chunk = []
        
        # Use tqdm for progress tracking
        with tqdm(total=self.max_passwords) as pbar:
            for password in self.password_generator():
                current_chunk.append(password)
                
                if len(current_chunk) >= self.chunk_size:
                    # Process the current chunk
                    chunk_features = self.process_chunk(current_chunk)
                    all_features.append(chunk_features)
                    
                    # Update progress and clear memory
                    passwords_processed += len(current_chunk)
                    pbar.update(len(current_chunk))
                    current_chunk = []
                    gc.collect()  # Force garbage collection
                    
                if passwords_processed >= self.max_passwords:
                    break
            
            # Process any remaining passwords
            if current_chunk:
                chunk_features = self.process_chunk(current_chunk)
                all_features.append(chunk_features)
                pbar.update(len(current_chunk))
        
        # Combine all features
        print("\nCombining features...")
        final_features = pd.concat(all_features, ignore_index=True)
        
        # Calculate strength score based on features
        print("Calculating strength scores...")
        final_features['strength_score'] = self._calculate_strength_score(final_features)
        
        print(f"Total passwords processed: {len(final_features)}")
        return final_features

    def _calculate_strength_score(self, df):
        """Calculate password strength score based on features."""
        # Base score from length (0-40 points)
        length_score = df['length'].apply(lambda x: min(40, x * 2))
        
        # Character variety score (0-30 points)
        variety_score = (
            (df['has_lowercase'] * 5) +
            (df['has_uppercase'] * 10) +
            (df['has_digit'] * 7) +
            (df['has_special'] * 8)
        )
        
        # Complexity score based on character counts (0-30 points)
        complexity_score = (
            (df['uppercase_count'] * 1.5) +
            (df['digit_count'] * 1.0) +
            (df['special_char_count'] * 2.0)
        ).apply(lambda x: min(30, x))
        
        # Combine scores and normalize to 0-100
        total_score = (length_score + variety_score + complexity_score).clip(0, 100)
        
        return total_score

    def get_feature_names(self):
        """Return list of feature names."""
        return ['length', 'uppercase_count', 'lowercase_count', 'digit_count',
                'special_char_count', 'has_alpha', 'has_digit', 'has_special',
                'has_uppercase', 'has_lowercase']

    def _calculate_entropy(self, password):
        """Calculate Shannon entropy of password."""
        freq = Counter(password)
        entropy = 0
        for count in freq.values():
            p = count / len(password)
            entropy -= p * np.log2(p)
        return entropy

    def split_dataset(self, df, test_size=0.2, val_size=0.1):
        """Split dataset into train, validation, and test sets."""
        X = df.drop('strength_score', axis=1)
        y = df['strength_score']
        
        # First split: separate test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )
        
        # Second split: separate validation set from training set
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=42
        )
        
        return (X_train, y_train), (X_val, y_val), (X_test, y_test) 