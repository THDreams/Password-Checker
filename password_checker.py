import string
import itertools
import time
import math
from multiprocessing import Pool, cpu_count

def calculate_entropy(password):
    char_sets = {
        'uppercase': string.ascii_uppercase,
        'lowercase': string.ascii_lowercase,
        'digits': string.digits,
        'special': string.punctuation
    }
    
    pool_size = sum(len(char_set) for char_set, chars in char_sets.items() 
                   if any(c in chars for c in password))
    return math.log2(pool_size) * len(password)

def check_password_strength(password):
    score = 0
    checks = {
        'length': len(password) >= 8,
        'digits': any(c.isdigit() for c in password),
        'upper': any(c.isupper() for c in password),
        'lower': any(c.islower() for c in password),
        'special': any(c in string.punctuation for c in password)
    }
    return sum(checks.values()), checks

def attempt_crack_password(password, max_length=8):
    chars = string.ascii_letters + string.digits + string.punctuation
    attempts = 0
    start_time = time.time()
    
    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            current = ''.join(guess)
            print(f"Testing: {current} | Attempts: {attempts}", end='\r')
            
            if current == password:
                end_time = time.time()
                print("\nPassword found!")
                return attempts, end_time - start_time
    
    return None

def estimate_crack_time(entropy):
    guesses_per_second = 1000000
    seconds = 2**entropy / guesses_per_second
    
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        return f"{seconds/31536000:.1f} years"

def main():
    print("=== Password Strength Checker and Cracker ===")
    while True:
        password = input("\nEnter a password to test: ")
        if password:
            break
        print("Password cannot be empty! Try again.")
    
    print("\nAttempting to crack password...")
    result = attempt_crack_password(password)
    
    print("\n=== Password Analysis Report ===")
    
    if result:
        attempts, duration = result
        print(f"\nPassword Cracked!")
        print(f"Attempts needed: {attempts:,}")
        print(f"Time taken: {duration:.2f} seconds")
    else:
        print("\nPassword not cracked within brute force limits")
    
    score, checks = check_password_strength(password)
    entropy = calculate_entropy(password)
    
    print("\nStrength Metrics:")
    print(f"Length: {len(password)} characters")
    print(f"Entropy: {entropy:.1f} bits")
    print(f"Strength Score: {score}/5")
    
    print("\nChecks Passed:")
    print(f"{'Pass' if checks['length'] else 'Fail'} - Length >= 8")
    print(f"{'Pass' if checks['digits'] else 'Fail'} - Contains numbers")
    print(f"{'Pass' if checks['upper'] else 'Fail'} - Contains uppercase")
    print(f"{'Pass' if checks['lower'] else 'Fail'} - Contains lowercase")
    print(f"{'Pass' if checks['special'] else 'Fail'} - Contains special characters")
    
    print(f"\nEstimated crack time: {estimate_crack_time(entropy)}")
    
    if score < 5:
        print("\nRecommendations to improve:")
        if not checks['length']:
            print("- Make password longer (at least 8 characters)")
        if not checks['digits']:
            print("- Add numbers")
        if not checks['upper']:
            print("- Add uppercase letters")
        if not checks['lower']:
            print("- Add lowercase letters")
        if not checks['special']:
            print("- Add special characters")

if __name__ == "__main__":
    main()
