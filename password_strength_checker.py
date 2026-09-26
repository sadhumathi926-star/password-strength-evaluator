#!/usr/bin/env python3
"""
Password Strength Evaluator
----------------------------
Evaluates password strength using:
  1. Security policy criteria (length, character classes)
  2. Shannon entropy calculation based on character pool size
  3. Common/leaked password dictionary check
  4. Strength classification: Weak / Moderate / Strong / Exceptional
  5. Actionable feedback for the user

Usage:
    python password_strength_checker.py
    python password_strength_checker.py --password "MyP@ssw0rd123"
    python password_strength_checker.py --batch passwords.txt
"""

import argparse
import math
import re
import sys
import getpass

# --------------------------------------------------------------------------
# 1. Common / leaked password list (small built-in sample of well-known
#    breached passwords). In production, replace with a full dataset such
#    as "rockyou.txt" or "Have I Been Pwned" API lookups (k-anonymity model).
# --------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "12345", "12345678",
    "111111", "1234567", "sunshine", "iloveyou", "princess", "admin",
    "welcome", "666666", "abc123", "football", "monkey", "letmein",
    "login", "starwars", "123123", "dragon", "passw0rd", "master",
    "hello", "freedom", "whatever", "qazwsx", "trustno1", "654321",
    "jordan23", "harley", "password1", "1234", "12345", "michael",
    "superman", "batman", "tigger", "shadow", "hottie", "chelsea"
}


# --------------------------------------------------------------------------
# 2. Security Policy Definition
# --------------------------------------------------------------------------
class PasswordPolicy:
    def __init__(self,
                 min_length=8,
                 require_upper=True,
                 require_lower=True,
                 require_digit=True,
                 require_special=True,
                 min_special_count=1):
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
        self.min_special_count = min_special_count

    def evaluate(self, password: str) -> dict:
        """Return a dict of policy checks -> bool, plus a list of failures."""
        checks = {
            "length_ok": len(password) >= self.min_length,
            "has_upper": bool(re.search(r"[A-Z]", password)) if self.require_upper else True,
            "has_lower": bool(re.search(r"[a-z]", password)) if self.require_lower else True,
            "has_digit": bool(re.search(r"\d", password)) if self.require_digit else True,
            "has_special": len(re.findall(r"[^A-Za-z0-9]", password)) >= self.min_special_count
                           if self.require_special else True,
        }
        failures = [k for k, v in checks.items() if not v]
        checks["policy_compliant"] = len(failures) == 0
        checks["failures"] = failures
        return checks


# --------------------------------------------------------------------------
# 3. Entropy Calculation
# --------------------------------------------------------------------------
def estimate_char_pool_size(password: str) -> int:
    """
    Estimate the character pool size (alphabet size) actually used,
    which determines the theoretical entropy per character.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32  # approx count of common special characters on a keyboard
    return pool if pool > 0 else 1


def calculate_entropy(password: str) -> float:
    """
    Shannon-style entropy estimate (bits):
        entropy = length * log2(pool_size)
    Higher entropy => harder to brute-force.
    """
    pool_size = estimate_char_pool_size(password)
    length = len(password)
    if length == 0:
        return 0.0
    return length * math.log2(pool_size)


def estimate_crack_time_seconds(entropy_bits: float, guesses_per_second: float = 1e10) -> float:
    """
    Rough offline brute-force crack time estimate assuming an attacker
    can attempt `guesses_per_second` guesses (1e10 ~ modern GPU cluster).
    """
    total_combinations = 2 ** entropy_bits
    return total_combinations / guesses_per_second


def human_readable_time(seconds: float) -> str:
    intervals = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    if seconds < 1:
        return "less than a second"
    for name, count in intervals:
        value = seconds / count
        if value >= 1:
            if value > 1e6:
                return f"{value:.2e} {name}"
            return f"{value:.1f} {name}"
    return "instantly"


# --------------------------------------------------------------------------
# 4. Dictionary / Breach Check
# --------------------------------------------------------------------------
def is_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


# --------------------------------------------------------------------------
# 5. Strength Classification
# --------------------------------------------------------------------------
def classify_strength(entropy_bits: float, policy_compliant: bool, is_leaked: bool) -> str:
    """
    Classification rules:
      - Any leaked/common password       -> Weak (regardless of entropy)
      - Entropy < 28 bits                -> Weak
      - Entropy 28-35 and policy fails    -> Weak
      - Entropy 36-59                    -> Moderate
      - Entropy 60-79 and policy passes  -> Strong
      - Entropy >= 80 and policy passes  -> Exceptional
    """
    if is_leaked:
        return "Weak"
    if entropy_bits < 28:
        return "Weak"
    if entropy_bits < 36:
        return "Weak" if not policy_compliant else "Moderate"
    if entropy_bits < 60:
        return "Moderate"
    if entropy_bits < 80:
        return "Strong" if policy_compliant else "Moderate"
    return "Exceptional" if policy_compliant else "Strong"


# --------------------------------------------------------------------------
# 6. Feedback Generator
# --------------------------------------------------------------------------
def generate_feedback(password: str, policy_result: dict, is_leaked: bool, entropy_bits: float) -> list:
    feedback = []

    if is_leaked:
        feedback.append("This password appears in known breach/common-password lists. Choose a completely different one.")

    if "length_ok" in policy_result["failures"]:
        feedback.append("Increase length to at least the policy minimum (aim for 12+ characters for good margin).")
    if "has_upper" in policy_result["failures"]:
        feedback.append("Add at least one uppercase letter (A-Z).")
    if "has_lower" in policy_result["failures"]:
        feedback.append("Add at least one lowercase letter (a-z).")
    if "has_digit" in policy_result["failures"]:
        feedback.append("Add at least one digit (0-9).")
    if "has_special" in policy_result["failures"]:
        feedback.append("Add at least one special character (e.g. ! @ # $ % ^ & *).")

    if re.search(r"(.)\1{2,}", password):
        feedback.append("Avoid repeating the same character three or more times in a row.")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)", password.lower()):
        feedback.append("Avoid common sequential patterns (e.g. '1234', 'abcd', 'qwerty').")

    if entropy_bits < 60 and not feedback:
        feedback.append("Consider using a longer passphrase (4+ random words) to increase entropy further.")

    if not feedback:
        feedback.append("Excellent password. No further action needed.")

    return feedback


# --------------------------------------------------------------------------
# 7. Main Evaluation Pipeline
# --------------------------------------------------------------------------
def evaluate_password(password: str, policy: PasswordPolicy) -> dict:
    policy_result = policy.evaluate(password)
    entropy_bits = calculate_entropy(password)
    crack_seconds = estimate_crack_time_seconds(entropy_bits)
    leaked = is_common_password(password)
    strength = classify_strength(entropy_bits, policy_result["policy_compliant"], leaked)
    feedback = generate_feedback(password, policy_result, leaked, entropy_bits)

    return {
        "password_length": len(password),
        "entropy_bits": round(entropy_bits, 2),
        "estimated_crack_time": human_readable_time(crack_seconds),
        "policy_compliant": policy_result["policy_compliant"],
        "policy_failures": policy_result["failures"],
        "is_common_or_leaked": leaked,
        "strength_score": strength,
        "feedback": feedback,
    }


def print_report(password: str, result: dict):
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)
    print("=" * 60)
    print(f" Password Strength Report  ({masked})")
    print("=" * 60)
    print(f" Length              : {result['password_length']}")
    print(f" Entropy (bits)      : {result['entropy_bits']}")
    print(f" Est. Crack Time     : {result['estimated_crack_time']}")
    print(f" Policy Compliant    : {'Yes' if result['policy_compliant'] else 'No'}")
    if result["policy_failures"]:
        print(f" Policy Failures     : {', '.join(result['policy_failures'])}")
    print(f" Common/Leaked List  : {'YES - FOUND' if result['is_common_or_leaked'] else 'No'}")
    print(f" Strength Score      : {result['strength_score'].upper()}")
    print("-" * 60)
    print(" Feedback:")
    for i, tip in enumerate(result["feedback"], 1):
        print(f"   {i}. {tip}")
    print("=" * 60)
    print()


# --------------------------------------------------------------------------
# 8. CLI Entry Point
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Strength & Entropy Evaluator")
    parser.add_argument("--password", "-p", help="Password to evaluate directly (not recommended on shared terminals)")
    parser.add_argument("--batch", "-b", help="Path to a text file with one password per line to evaluate in batch")
    parser.add_argument("--min-length", type=int, default=8, help="Minimum required length for policy (default: 8)")
    args = parser.parse_args()

    policy = PasswordPolicy(min_length=args.min_length)

    if args.batch:
        try:
            with open(args.batch, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: file '{args.batch}' not found.")
            sys.exit(1)

        for pw in passwords:
            result = evaluate_password(pw, policy)
            print_report(pw, result)
        return

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password to evaluate (input hidden): ")

    result = evaluate_password(password, policy)
    print_report(password, result)


if __name__ == "__main__":
    main()
