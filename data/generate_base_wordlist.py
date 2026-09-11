"""
Generates data/base_wordlist.txt — 500 curated passwords spanning difficulty
levels, used as the seed for the Tier 1 ("meet hashcat") custom wordlist.
Real attendee passwords get inserted into this list later (see app.py).
Run once: python3 generate_base_wordlist.py
"""
import random

random.seed(42)

weak_words = [
    "password", "123456", "qwerty", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "baseball", "sunshine", "princess",
    "azerty", "trustno1", "master", "hello", "freedom", "whatever", "shadow",
    "superman", "batman", "ninja", "starwars", "pokemon", "flower", "tigger",
    "cheese", "chocolate", "cookie", "pizza", "coffee", "soccer", "hockey",
    "basketball", "tennis", "guitar", "music", "movie", "friends", "family",
    "summer", "winter", "spring", "autumn", "ocean", "mountain", "forest",
    "river", "island", "desert",
]

names = [
    "ahmed", "mohamed", "youssef", "khaled", "sami", "rayen", "yassine",
    "amine", "wassim", "mehdi", "walid", "karim", "nour", "rania", "sarra",
    "yasmine", "ines", "salma", "amira", "mariem", "asma", "hiba", "syrine",
    "tunis", "sousse", "sfax", "carthage", "kairouan", "djerba", "bizerte",
    "manar", "elmanar", "isi", "securinets", "esprit", "insat", "supcom",
]

tech_words = [
    "hacker", "cyber", "matrix", "phoenix", "shadow", "ghost", "cipher",
    "root", "admin", "system", "network", "firewall", "kernel", "binary",
    "exploit", "payload", "breach", "packet", "socket", "daemon", "script",
    "bug", "virus", "trojan", "worm", "phishing", "malware", "ransomware",
]

sports_teams = [
    "esperance", "etoile", "clubafricain", "csS", "usmonastir", "cavaliers",
    "realmadrid", "barcelona", "juventus", "liverpool", "chelsea", "psg",
]

def leet(word):
    subs = {"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"}
    return "".join(subs.get(c, c) for c in word)

base_pool = weak_words + names + tech_words + sports_teams
random.shuffle(base_pool)

entries = set()

# Tier: weak (raw dictionary word, sometimes capitalized) — ~150
pool_iter = iter(base_pool * 3)
while len([e for e in entries]) < 150:
    w = next(pool_iter)
    variant = random.choice([w, w.capitalize(), w.upper()])
    entries.add(variant)

# Tier: medium (word + digits) — ~150
count = 0
pool_iter = iter(base_pool * 3)
for w in pool_iter:
    if count >= 150:
        break
    suffix = random.choice(["123", "1234", "12345", "01", "99", "2023", "2024", "2025", "007"])
    variant = random.choice([w, w.capitalize()]) + suffix
    if variant not in entries:
        entries.add(variant)
        count += 1

# Tier: medium-strong (capitalized + digits + symbol) — ~150
count = 0
pool_iter = iter(base_pool * 3)
for w in pool_iter:
    if count >= 150:
        break
    suffix = random.choice(["123!", "2024!", "2025@", "99#", "1!", "@123"])
    variant = w.capitalize() + suffix
    if variant not in entries:
        entries.add(variant)
        count += 1

# Tier: stronger-looking but still dictionary-based (leetspeak / longer combos) — ~50
count = 0
pool_iter = iter(base_pool * 5)
for w in pool_iter:
    if count >= 50:
        break
    style = random.choice([
        leet(w) + str(random.randint(1, 999)) + "!",
        w.capitalize() + random.choice(names).capitalize() + "!",
        leet(w).capitalize() + "@" + str(random.randint(1900, 2025)),
    ])
    if style not in entries:
        entries.add(style)
        count += 1

entries = list(entries)[:500]
while len(entries) < 500:
    # pad if we came up short due to collisions
    extra = random.choice(base_pool) + str(random.randint(1000, 9999))
    if extra not in entries:
        entries.append(extra)

random.shuffle(entries)

with open("base_wordlist.txt", "w") as f:
    f.write("\n".join(entries[:500]) + "\n")

print(f"Wrote {len(entries[:500])} entries to base_wordlist.txt")
