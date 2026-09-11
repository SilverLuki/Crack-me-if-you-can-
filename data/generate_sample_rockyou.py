"""
Generates data/sample_rockyou.txt — a SMALL PLACEHOLDER standing in for the
real rockyou.txt (which has ~14 million real leaked passwords and isn't
something this sandbox can download).

BEFORE THE REAL EVENT: replace data/sample_rockyou.txt with the real file,
e.g. /usr/share/wordlists/rockyou.txt from Kali, or the first 50k-100k lines
of it (see README.md — using the first ~100k lines keeps tier-2 cracks fast
since rockyou is already ordered roughly by real-world frequency).
"""
import random
random.seed(7)

words = [
    "sunshine", "butterfly", "elephant", "chocolate", "strawberry", "rainbow",
    "unicorn", "dolphin", "penguin", "giraffe", "hamburger", "spaghetti",
    "wonderland", "adventure", "treasure", "mystery", "journey", "victory",
    "freedom", "harmony", "destiny", "fantasy", "melody", "serenity",
    "gladiator", "warrior", "champion", "legend", "phoenix", "dragonfly",
    "moonlight", "starlight", "sunflower", "waterfall", "hurricane", "tornado",
    "avalanche", "volcano", "earthquake", "lightning", "thunder", "blizzard",
    "guitar", "piano", "violin", "trumpet", "saxophone", "drums", "cello",
    "basketball", "volleyball", "badminton", "wrestling", "gymnastics",
    "computer", "keyboard", "monitor", "printer", "internet", "software",
    "sandwich", "hamburger", "pancake", "omelette", "croissant", "baguette",
    "elephant7", "tiger2020", "lion1999", "panther88", "cheetah55",
]

with open("sample_rockyou.txt", "w") as f:
    for w in words:
        f.write(w + "\n")
        f.write(w + str(random.randint(1, 99)) + "\n")
        f.write(w.capitalize() + "\n")

print("Wrote sample_rockyou.txt (PLACEHOLDER — replace before the real event)")
