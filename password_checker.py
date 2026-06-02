import re
import math


COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "dragon", "master", "iloveyou", "sunshine", "princess",
    "football", "shadow", "admin", "login", "pass", "test", "hello", "batman"
}


def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0
    return int(len(password) * math.log2(pool))


def crack_time_estimate(entropy):
    guesses_per_sec = 1e10  # fast offline attack
    combos = 2 ** entropy
    secs = combos / guesses_per_sec

    if secs < 1:
        return "less than 1 second"
    elif secs < 60:
        return f"{int(secs)} second(s)"
    elif secs < 3600:
        return f"{int(secs // 60)} minute(s)"
    elif secs < 86400:
        return f"{int(secs // 3600)} hour(s)"
    elif secs < 2_592_000:
        return f"{int(secs // 86400)} day(s)"
    elif secs < 31_536_000:
        return f"{int(secs // 2_592_000)} month(s)"
    else:
        years = secs / 31_536_000
        if years < 1_000_000:
            return f"{int(years):,} year(s)"
        elif years < 1_000_000_000:
            return f"{years / 1_000_000:.1f} million year(s)"
        else:
            return "over 1 billion years"


def check_criteria(password):
    return {
        "min_8_chars":    len(password) >= 8,
        "min_12_chars":   len(password) >= 12,
        "has_uppercase":  bool(re.search(r"[A-Z]", password)),
        "has_lowercase":  bool(re.search(r"[a-z]", password)),
        "has_numbers":    bool(re.search(r"[0-9]", password)),
        "has_special":    bool(re.search(r"[^a-zA-Z0-9]", password)),
        "not_common":     password.lower() not in COMMON_PASSWORDS,
        "min_16_chars":   len(password) >= 16,
    }


def score_password(criteria, is_common):
    score = sum([
        criteria["min_8_chars"],
        criteria["min_12_chars"],
        criteria["has_uppercase"],
        criteria["has_lowercase"],
        criteria["has_numbers"],
        criteria["has_special"],
        criteria["min_16_chars"],
        criteria["not_common"],
    ])
    score = min(score, 7)
    if is_common:
        score = min(score, 1)
    return score


def classify(score):
    if score <= 2:
        return "WEAK"
    elif score <= 4:
        return "MEDIUM"
    elif score <= 5:
        return "GOOD"
    else:
        return "STRONG"


def get_suggestions(password, criteria):
    suggestions = []
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("⚠  This is a commonly known password — avoid it entirely.")
    if not criteria["min_8_chars"]:
        suggestions.append("→  Use at least 8 characters (12+ is much better).")
    elif not criteria["min_12_chars"]:
        suggestions.append("→  Aim for 12 or more characters to increase strength.")
    if not criteria["has_uppercase"]:
        suggestions.append("→  Add uppercase letters (A–Z).")
    if not criteria["has_lowercase"]:
        suggestions.append("→  Add lowercase letters (a–z).")
    if not criteria["has_numbers"]:
        suggestions.append("→  Include at least one number (0–9).")
    if not criteria["has_special"]:
        suggestions.append("→  Add special characters like !@#$%^&*().")
    if criteria["min_12_chars"] and not criteria["min_16_chars"]:
        suggestions.append("→  Consider a passphrase (4+ random words) for even more security.")
    if not suggestions:
        suggestions.append("✓  Great password! No major improvements needed.")
    return suggestions


def check_password(password):
    is_common = password.lower() in COMMON_PASSWORDS
    criteria   = check_criteria(password)
    score      = score_password(criteria, is_common)
    level      = classify(score)
    entropy    = calculate_entropy(password)
    crack_time = crack_time_estimate(entropy)
    suggestions = get_suggestions(password, criteria)

    sep = "─" * 52

    print(f"\n{sep}")
    print(f"  Password Strength Report")
    print(sep)
    print(f"  Strength  : {level}")
    print(f"  Length    : {len(password)} characters")
    print(f"  Entropy   : ~{entropy} bits")
    print(f"  Crack time: {crack_time}  (at 10B guesses/sec)")
    print(sep)

    print("  Criteria:")
    labels = {
        "min_8_chars":   "At least 8 characters",
        "min_12_chars":  "At least 12 characters",
        "has_uppercase": "Uppercase letters (A–Z)",
        "has_lowercase": "Lowercase letters (a–z)",
        "has_numbers":   "Numbers (0–9)",
        "has_special":   "Special characters (!@#…)",
        "not_common":    "Not a common password",
        "min_16_chars":  "At least 16 characters",
    }
    for key, label in labels.items():
        mark = "✓" if criteria[key] else "✗"
        print(f"    {mark}  {label}")

    print(sep)
    print("  Suggestions:")
    for s in suggestions:
        print(f"    {s}")
    print(sep + "\n")


def main():
    print("=" * 52)
    print("       Task 02 — Password Strength Checker")
    print("=" * 52)
    print("  Evaluates length, character variety, entropy,")
    print("  and common-password detection.")
    print("  Type 'quit' to exit.\n")

    while True:
        password = input("  Enter password: ")
        if password.lower() == "quit":
            print("\n  Goodbye!\n")
            break
        if not password:
            print("  Please enter a password.\n")
            continue
        check_password(password)


if __name__ == "__main__":
    main()
