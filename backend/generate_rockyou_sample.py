import requests
import random
import os

def download_rockyou_sample():
    """Download a sample of the RockYou dataset."""
    # URL for the RockYou dataset (this is a small sample)
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-10.txt"
    
    try:
        # Download the file
        response = requests.get(url)
        response.raise_for_status()
        
        # Convert to list and clean up
        passwords = response.text.splitlines()
        passwords = [p.strip() for p in passwords if p.strip()]
        
        # Take a random sample of 1000 passwords
        sample = random.sample(passwords, min(1000, len(passwords)))
        
        # Save to file
        with open('rockyou_sample.txt', 'w', encoding='utf-8') as f:
            for password in sample:
                f.write(password + '\n')
        
        print(f"Successfully created rockyou_sample.txt with {len(sample)} passwords")
        
    except Exception as e:
        print(f"Error downloading RockYou dataset: {e}")
        # Create a minimal sample if download fails
        minimal_sample = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "letmein", "dragon", "111111", "baseball",
            "iloveyou", "trustno1", "superman", "sunshine", "master"
        ]
        with open('rockyou_sample.txt', 'w', encoding='utf-8') as f:
            for password in minimal_sample:
                f.write(password + '\n')
        print("Created minimal password sample as fallback")

if __name__ == "__main__":
    download_rockyou_sample() 