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
    
    def estimate_crack_time(self, password: str) -> Dict[str, Dict[str, Any]]:
        """Estimate time to crack password using various attack methods."""
        # Calculate base metrics
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        # Calculate character space
        char_space = 0
        if has_lower: char_space += 26
        if has_upper: char_space += 26
        if has_digit: char_space += 10
        if has_special: char_space += 33  # Common special characters
        
        # Attack speeds (attempts per second)
        BRUTE_FORCE_SPEED = 1_000_000_000  # 1 billion/sec (high-end GPU)
        DICTIONARY_SPEED = 10_000_000      # 10 million/sec
        PATTERN_SPEED = 100_000_000       # 100 million/sec
        TARGETED_SPEED = 1_000            # 1000/sec
        
        def format_time(seconds: float) -> str:
            """Format time in a human-readable way."""
            if seconds < 0.000001:
                return "instantly"
            elif seconds < 0.001:
                return f"{seconds*1000000:.1f} microseconds"
            elif seconds < 1:
                return f"{seconds*1000:.1f} milliseconds"
            elif seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 2592000:  # 30 days
                return f"{seconds/86400:.1f} days"
            elif seconds < 31536000:  # 1 year
                return f"{seconds/2592000:.1f} months"
            elif seconds < 315360000:  # 10 years
                return f"{seconds/31536000:.1f} years"
            elif seconds < 3153600000:  # 100 years
                return f"{seconds/31536000:.0f} years"
            else:
                return "centuries"
        
        # Calculate brute force time
        brute_combinations = char_space ** length
        brute_seconds = brute_combinations / BRUTE_FORCE_SPEED
        
        # Calculate dictionary attack time
        word_pattern = re.compile(r'[a-zA-Z]{3,}')
        words = word_pattern.findall(password)
        if words:
            dict_combinations = 171476 * (2 if has_upper else 1) * (2 if has_digit else 1) * (2 if has_special else 1)
            dict_seconds = dict_combinations / DICTIONARY_SPEED
        else:
            dict_seconds = float('inf')
        
        # Calculate pattern-based attack time
        has_pattern = bool(re.search(r'(.)\\1{2,}|123|abc|qwerty|password|admin', password.lower()))
        if has_pattern:
            pattern_combinations = 1000000 * (2 if has_upper else 1) * (2 if has_digit else 1) * (2 if has_special else 1)
            pattern_seconds = pattern_combinations / PATTERN_SPEED
        else:
            pattern_seconds = float('inf')
        
        # Calculate targeted attack time
        has_date = bool(re.search(r'19\d{2}|20\d{2}|[0-9]{6,8}', password))
        if has_date:
            targeted_combinations = 100000 * (2 if has_upper else 1) * (2 if has_special else 1)
            targeted_seconds = targeted_combinations / TARGETED_SPEED
        else:
            targeted_seconds = float('inf')
        
        # Calculate entropy contribution scores (0-100)
        def calc_entropy_contribution(seconds: float) -> float:
            if seconds == float('inf'):
                return 0
            return min(100, max(0, math.log2(seconds + 1) * 10))
        
        return {
            "brute_force": {
                "seconds": brute_seconds,
                "time_readable": format_time(brute_seconds),
                "entropy_contribution": calc_entropy_contribution(brute_seconds),
                "description": "Tries every possible combination of characters"
            },
            "dictionary": {
                "seconds": dict_seconds,
                "time_readable": format_time(dict_seconds),
                "entropy_contribution": calc_entropy_contribution(dict_seconds),
                "description": "Uses common words and variations"
            },
            "pattern_based": {
                "seconds": pattern_seconds,
                "time_readable": format_time(pattern_seconds),
                "entropy_contribution": calc_entropy_contribution(pattern_seconds),
                "description": "Exploits common patterns and keyboard layouts"
            },
            "targeted": {
                "seconds": targeted_seconds,
                "time_readable": format_time(targeted_seconds),
                "entropy_contribution": calc_entropy_contribution(targeted_seconds),
                "description": "Uses personal information and common dates"
            }
        }
    
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
    
    def generate_suggestions(self, password: str, patterns: List[Dict[str, Any]]) -> List[str]:
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
        """Perform comprehensive analysis of a password."""
        # Get crack times for different methods
        crack_times = self.estimate_crack_time(password)
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Identify patterns
        patterns = self.identify_patterns(password)
        
        # Generate suggestions
        suggestions = self.generate_suggestions(password, patterns)
        
        # Determine fastest crack method
        fastest_crack = min(crack_times.items(), key=lambda x: x[1]["seconds"])
        fastest_method = fastest_crack[0]
        fastest_time = fastest_crack[1]
        
        # Calculate overall strength score (0-100)
        time_score = min(100, 20 * sum(ct["entropy_contribution"]/100 for ct in crack_times.values()))
        pattern_penalty = len(patterns) * 10
        final_score = max(0, min(100, time_score - pattern_penalty))
        
        # Determine category
        if final_score < 20:
            category = "Very Weak"
        elif final_score < 40:
            category = "Weak"
        elif final_score < 60:
            category = "Moderate"
        elif final_score < 80:
            category = "Strong"
        else:
            category = "Very Strong"
        
        return {
            "category": category,
            "score": final_score,
            "entropy": entropy,
            "crack_times": crack_times,
            "patterns": patterns,
            "suggestions": suggestions,
            "fastest_crack": {
                "method": fastest_method,
                "time": fastest_time["time_readable"],
                "description": fastest_time["description"]
            }
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