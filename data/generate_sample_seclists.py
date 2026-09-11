"""
Generates data/sample_seclists.txt — a SMALL PLACEHOLDER standing in for a
real SecLists wordlist (install via `apt install seclists` on Kali, or
clone https://github.com/danielmiessler/SecLists).

BEFORE THE REAL EVENT: replace data/sample_seclists.txt with a real list,
e.g. SecLists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
"""
import random
random.seed(11)

words = [
    "securinets", "pentest", "redteam", "blueteam", "capture", "flagfinder",
    "vulnerability", "exploitdb", "burpsuite", "wireshark", "nmapscan",
    "metasploit", "kalilinux", "hashcat", "johntheripper", "sqlinjection",
    "crosssite", "bufferoverflow", "privesc", "reverseshell", "webshell",
    "isimanar", "sorbonne", "esprittn", "insattn", "supcomtn",
    "carthage2025", "tunisie2025", "manartn", "elmanar2025",
    "ctfplayer", "bugbounty", "zeroday", "payloadx", "shellcode",
]

with open("sample_seclists.txt", "w") as f:
    for w in words:
        f.write(w + "\n")
        f.write(w + str(random.randint(1, 99)) + "\n")
        f.write(w.capitalize() + "!" + "\n")

print("Wrote sample_seclists.txt (PLACEHOLDER — replace before the real event)")
