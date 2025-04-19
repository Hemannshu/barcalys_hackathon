import math
from typing import Dict

def analyze_password(password: str) -> Dict[str, any]:
    """Analyze password strength and return metrics."""
    if not password:
        return {
            "strength": 0,
            "crack_time": "instantly",
            "entropy": 0,
            "suggestions": []
        }

    # 1. Calculate character set size
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(not c.isalnum() for c in password): charset += 32

    # 2. Calculate entropy (bits)
    entropy = len(password) * math.log2(charset) if charset else 0

    # 3. Estimate crack time (simplified)
    # Assuming bcrypt at 1k hashes/second
    crack_time_seconds = (2 ** entropy) / 1000

    # 4. Format crack time human-readably
    def format_time(seconds: float) -> str:
        if seconds < 1: return "instantly"
        if seconds < 60: return f"{seconds:.1f} seconds"
        if seconds < 3600: return f"{seconds/60:.1f} minutes"
        if seconds < 86400: return f"{seconds/3600:.1f} hours"
        if seconds < 31536000: return f"{seconds/86400:.1f} days"
        return f"{seconds/31536000:.1f} years"

    # 5. Generate basic suggestions
    suggestions = [
        f"{password}{'!' * math.ceil(len(password)/4)}",
        f"{password[:len(password)//2]}!{password[len(password)//2:]}",
        password.upper() + str(len(password))
    ]

    return {
        "strength": min(100, int(entropy * 1.5)),  # Scale to 0-100
        "crack_time": format_time(crack_time_seconds),
        "entropy": round(entropy, 2),
        "suggestions": suggestions,
        "charset_size": charset
    }