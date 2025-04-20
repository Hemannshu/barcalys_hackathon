import re
import math
import random
import string
import numpy as np
from collections import Counter
import hashlib
import time
import os
import json
from typing import Dict, List, Tuple, Any

class PasswordAnalyzer:
    def __init__(self):
        # Load common password patterns and dictionaries
        self.common_patterns = self._load_common_patterns()
        self.weak_passwords = self._load_weak_passwords()
        
        # Character sets for entropy calculation
        self.lowercase = set(string.ascii_lowercase)
        self.uppercase = set(string.ascii_uppercase)
        self.digits = set(string.digits)
        self.special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
        
        # Hash algorithms and their relative speeds (operations per second)
        self.hash_algorithms = {
            'md5': 1000000000,  # 1 billion ops/sec
            'sha1': 500000000,  # 500 million ops/sec
            'sha256': 100000000,  # 100 million ops/sec
            'bcrypt': 10000,  # 10 thousand ops/sec
        }
    
    def _load_common_patterns(self) -> Dict[str, List[str]]:
        """Load common password patterns from a JSON file or return defaults."""
        try:
            with open('common_patterns.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Default patterns if file doesn't exist
            return {
                "dates": ["YYYY", "MMDD", "DDMM", "YYYYMMDD"],
                "names": ["admin", "password", "qwerty", "123456"],
                "sequences": ["12345", "abcde", "qwerty", "asdfgh"],
                "keyboard_patterns": ["qwerty", "asdfgh", "zxcvbn", "1qaz2wsx"]
            }
    
    def _load_weak_passwords(self) -> List[str]:
        """Load weak passwords from a file or return defaults."""
        try:
            with open('rockyou_sample.txt', 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default weak passwords if file doesn't exist
            return ["password", "123456", "qwerty", "admin", "welcome", "letmein"]
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate the entropy of a password in bits."""
        # Count character types
        has_lower = any(c in self.lowercase for c in password)
        has_upper = any(c in self.uppercase for c in password)
        has_digit = any(c in self.digits for c in password)
        has_special = any(c in self.special_chars for c in password)
        
        # Calculate character pool size
        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_special: pool_size += 32
        
        # Calculate entropy
        entropy = len(password) * math.log2(pool_size)
        return entropy
    
    def estimate_crack_time(self, password: str) -> Dict[str, Any]:
        """Estimate the time to crack a password using different hash algorithms."""
        results = {}
        
        for algo, ops_per_sec in self.hash_algorithms.items():
            # Calculate number of possible combinations
            # This is a simplification - in reality, attackers use optimized methods
            entropy = self.calculate_entropy(password)
            combinations = 2 ** entropy
            
            # Estimate time in seconds
            seconds = combinations / ops_per_sec
            
            # Convert to human-readable format
            if seconds < 60:
                time_str = f"{seconds:.2f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds/60:.2f} minutes"
            elif seconds < 86400:
                time_str = f"{seconds/3600:.2f} hours"
            elif seconds < 31536000:
                time_str = f"{seconds/86400:.2f} days"
            else:
                time_str = f"{seconds/31536000:.2f} years"
            
            results[algo] = {
                "time_seconds": seconds,
                "time_readable": time_str,
                "entropy_bits": entropy
            }
        
        return results
    
    def identify_patterns(self, password: str) -> List[Dict[str, Any]]:
        """Identify common patterns in the password."""
        patterns = []
        
        # Check for common sequences
        for pattern_type, pattern_list in self.common_patterns.items():
            for pattern in pattern_list:
                if pattern.lower() in password.lower():
                    patterns.append({
                        "type": pattern_type,
                        "pattern": pattern,
                        "severity": "high" if pattern_type in ["sequences", "keyboard_patterns"] else "medium"
                    })
        
        # Check for dates (YYYY, MM/DD, etc.)
        date_patterns = [
            r'\d{4}',  # YYYY
            r'\d{2}/\d{2}',  # MM/DD
            r'\d{2}-\d{2}',  # MM-DD
            r'\d{6}',  # YYMMDD
            r'\d{8}'   # YYYYMMDD
        ]
        
        for pattern in date_patterns:
            if re.search(pattern, password):
                patterns.append({
                    "type": "date",
                    "pattern": re.search(pattern, password).group(0),
                    "severity": "medium"
                })
        
        # Check for dictionary words
        words = re.findall(r'[a-zA-Z]+', password)
        for word in words:
            if word.lower() in self.weak_passwords:
                patterns.append({
                    "type": "dictionary_word",
                    "pattern": word,
                    "severity": "high"
                })
        
        return patterns
    
    def generate_suggestions(self, password: str) -> List[str]:
        """Generate suggestions to improve password strength."""
        suggestions = []
        
        # Check length
        if len(password) < 12:
            suggestions.append(f"Increase length to at least 12 characters (currently {len(password)})")
        
        # Check character types
        has_lower = any(c in self.lowercase for c in password)
        has_upper = any(c in self.uppercase for c in password)
        has_digit = any(c in self.digits for c in password)
        has_special = any(c in self.special_chars for c in password)
        
        if not has_lower:
            suggestions.append("Add lowercase letters")
        if not has_upper:
            suggestions.append("Add uppercase letters")
        if not has_digit:
            suggestions.append("Add numbers")
        if not has_special:
            suggestions.append("Add special characters")
        
        # Check for common patterns
        patterns = self.identify_patterns(password)
        if patterns:
            for pattern in patterns:
                if pattern["severity"] == "high":
                    suggestions.append(f"Replace common pattern '{pattern['pattern']}' with something more random")
        
        # Generate specific suggestions
        if len(suggestions) > 0:
            # Create a stronger version of the password
            stronger = self._create_stronger_password(password)
            suggestions.append(f"Try this stronger password: {stronger}")
        
        return suggestions
    
    def _create_stronger_password(self, password: str) -> str:
        """Create a stronger version of the given password."""
        # Replace common patterns with random characters
        stronger = password
        
        # Replace lowercase letters with random case
        for i, c in enumerate(stronger):
            if c in self.lowercase:
                if random.random() > 0.5:
                    stronger = stronger[:i] + c.upper() + stronger[i+1:]
        
        # Replace numbers with similar-looking special characters
        number_to_special = {'1': '!', '2': '@', '3': '#', '4': '$', '5': '%', 
                            '6': '^', '7': '&', '8': '*', '9': '(', '0': ')'}
        
        for num, special in number_to_special.items():
            if num in stronger:
                stronger = stronger.replace(num, special)
        
        # Add special characters if missing
        if not any(c in self.special_chars for c in stronger):
            stronger += random.choice(list(self.special_chars))
        
        # Ensure minimum length
        while len(stronger) < 12:
            stronger += random.choice(list(self.special_chars | self.digits | self.uppercase | self.lowercase))
        
        return stronger
    
    def analyze_password(self, password: str) -> Dict[str, Any]:
        """Perform a comprehensive analysis of a password."""
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Estimate crack time
        crack_times = self.estimate_crack_time(password)
        
        # Identify patterns
        patterns = self.identify_patterns(password)
        
        # Generate suggestions
        suggestions = self.generate_suggestions(password)
        
        # Calculate overall strength score (0-100)
        strength_score = min(100, int(entropy * 5))
        
        # Adjust score based on patterns
        for pattern in patterns:
            if pattern["severity"] == "high":
                strength_score -= 20
            elif pattern["severity"] == "medium":
                strength_score -= 10
        
        # Ensure score is between 0 and 100
        strength_score = max(0, min(100, strength_score))
        
        # Determine strength category
        if strength_score >= 80:
            strength_category = "Very Strong"
        elif strength_score >= 60:
            strength_category = "Strong"
        elif strength_score >= 40:
            strength_category = "Moderate"
        elif strength_score >= 20:
            strength_category = "Weak"
        else:
            strength_category = "Very Weak"
        
        return {
            "password": password,
            "entropy_bits": entropy,
            "strength_score": strength_score,
            "strength_category": strength_category,
            "crack_times": crack_times,
            "patterns": patterns,
            "suggestions": suggestions,
            "attack_types": self._determine_attack_types(password, patterns)
        }
    
    def _determine_attack_types(self, password: str, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine which attack types would be most effective against this password."""
        attack_types = []
        
        # Dictionary attack
        if any(p["type"] == "dictionary_word" for p in patterns):
            attack_types.append({
                "name": "Dictionary Attack",
                "description": "Password contains common dictionary words that can be easily guessed",
                "risk_level": "High"
            })
        
        # Pattern-based attack
        if any(p["type"] in ["sequences", "keyboard_patterns"] for p in patterns):
            attack_types.append({
                "name": "Pattern-Based Attack",
                "description": "Password contains predictable keyboard patterns or sequences",
                "risk_level": "High"
            })
        
        # Brute force attack
        entropy = self.calculate_entropy(password)
        if entropy < 40:  # Less than 40 bits of entropy
            attack_types.append({
                "name": "Brute Force Attack",
                "description": "Password has low entropy and can be cracked with brute force in reasonable time",
                "risk_level": "Medium" if entropy > 30 else "High"
            })
        
        # Social engineering
        if any(p["type"] == "date" for p in patterns):
            attack_types.append({
                "name": "Social Engineering",
                "description": "Password contains dates that could be guessed through social engineering",
                "risk_level": "Medium"
            })
        
        return attack_types 