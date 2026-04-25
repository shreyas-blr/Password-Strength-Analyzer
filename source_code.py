import re
import math

# Common weak passwords
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "password123", "admin", "letmein", "welcome"
}

# Simple dictionary words (can be expanded)
COMMON_WORDS = {"hello", "india", "user", "login", "test"}


def calculate_entropy(password):
    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool += 32

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)
    return entropy


def check_patterns(password):
    issues = []

    # Repeated characters
    if re.search(r"(.)\1{2,}", password):
        issues.append("Avoid repeated characters (e.g., aaa)")

    # Sequential patterns
    sequences = ["123", "abc", "qwerty", "password"]
    for seq in sequences:
        if seq in password.lower():
            issues.append(f"Avoid predictable sequence: {seq}")

    return issues


def check_password_strength(password):
    score = 0
    feedback = []

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        return "Very Weak", 0, ["Common password detected"]

    # Dictionary word check
    for word in COMMON_WORDS:
        if word in password.lower():
            feedback.append("Avoid using common words")

    # Length scoring
    length = len(password)
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")

    # Character diversity
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Include numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Include special characters")

    # Pattern checks
    pattern_issues = check_patterns(password)
    if pattern_issues:
        feedback.extend(pattern_issues)
        score -= 1  # penalty

    # Entropy calculation
    entropy = calculate_entropy(password)

    # Strength classification based on entropy
    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength, entropy, feedback


def main():
    print("=== Advanced Password Strength Analyzer ===")
    password = input("Enter your password: ")

    strength, entropy, feedback = check_password_strength(password)

    print("\nStrength Level:", strength)
    print(f"Entropy Score: {entropy:.2f} bits")

    if feedback:
        print("\nSuggestions:")
        for f in feedback:
            print("-", f)
    else:
        print("\nExcellent password. No suggestions needed.")


if __name__ == "__main__":
    main()