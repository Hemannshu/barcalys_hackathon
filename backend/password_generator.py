import random
import string

# Common word replacements for password strength
REPLACEMENTS = {
    'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7',
    'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '$', 'T': '7'
}

# Special characters for adding complexity
SPECIAL_CHARS = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '[', ']', '{', '}', '|', ';', ':', '"', "'", '<', '>', ',', '.', '?', '/']

# Common words for password generation
WORDS = [
    'secure', 'strong', 'safe', 'guard', 'shield', 'protect', 'defend',
    'cyber', 'digital', 'tech', 'data', 'cloud', 'web', 'net', 'code',
    'crypto', 'quantum', 'matrix', 'vector', 'binary', 'logic', 'flow',
    'peak', 'summit', 'zen', 'nova', 'cosmic', 'stellar', 'galaxy',
    'phoenix', 'dragon', 'titan', 'atlas', 'zeus', 'thor', 'odin',
    'alpha', 'beta', 'delta', 'omega', 'sigma', 'theta', 'lambda'
]

def generate_password_from_base(base_password):
    """
    Generate a secure password based on a base password.
    
    Args:
        base_password (str): The base password to transform
        
    Returns:
        str: A secure password based on the base password
    """
    # Apply character replacements
    transformed = base_password
    for old, new in REPLACEMENTS.items():
        transformed = transformed.replace(old, new)
    
    # Add random special characters
    transformed += random.choice(SPECIAL_CHARS)
    transformed += random.choice(SPECIAL_CHARS)
    
    # Ensure minimum length of 12 characters
    while len(transformed) < 12:
        transformed += random.choice(string.ascii_letters + string.digits + ''.join(SPECIAL_CHARS))
    
    return transformed

def generate_password_from_existing(existing_password):
    """
    Generate a secure password based on an existing password.
    
    Args:
        existing_password (str): The existing password to transform
        
    Returns:
        str: A secure password based on the existing password
    """
    # Apply character replacements
    transformed = existing_password
    for old, new in REPLACEMENTS.items():
        transformed = transformed.replace(old, new)
    
    # Add special characters if not already present
    if not any(c in SPECIAL_CHARS for c in transformed):
        transformed += random.choice(SPECIAL_CHARS)
    
    # Ensure minimum length of 12 characters
    while len(transformed) < 12:
        transformed += random.choice(string.ascii_letters + string.digits + ''.join(SPECIAL_CHARS))
    
    return transformed

def generate_password(context, existing_password=''):
    """
    Generate a secure password based on context or existing password.
    
    Args:
        context (str): Context about the account or service
        existing_password (str, optional): Existing password to use as inspiration
        
    Returns:
        dict: Password data including the generated password, explanation, and memorization tips
    """
    # Generate password based on context or existing password
    if existing_password:
        # Use existing password as base
        base = existing_password
        generated_password = generate_password_from_existing(base)
        explanation = f"Password generated using pattern-based transformation of '{base}' with added complexity"
    else:
        # Generate from context or random words
        if len(context) >= 4:
            base = context[:8]  # Use first 8 chars of context
        else:
            base = random.choice(WORDS) + random.choice(WORDS)
        
        # Generate the password
        generated_password = generate_password_from_base(base)
        explanation = f"Password generated using pattern-based transformation of '{base}' with added complexity"
    
    # Calculate strength score (0-100)
    strength_score = min(100, len(generated_password) * 5 + 
                       sum(1 for c in generated_password if c in SPECIAL_CHARS) * 10 +
                       sum(1 for c in generated_password if c.isupper()) * 5 +
                       sum(1 for c in generated_password if c.islower()) * 5 +
                       sum(1 for c in generated_password if c.isdigit()) * 5)
    
    # Generate memorization tips
    memorization_tips = [
        "Break the password into meaningful chunks",
        "Create a story using the characters",
        "Use visual patterns to remember special characters",
        "Practice typing the password regularly"
    ]
    
    return {
        "password": generated_password,
        "explanation": explanation,
        "memorization_tips": memorization_tips,
        "strength_score": strength_score
    } 