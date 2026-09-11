"""
Crack Me If You Can — Securinets ISI first-event workshop backend.

Everyone brings their own Kali VM and runs hashcat locally against their
OWN target hash. This server's only jobs are:
  1. register players and score password strength
  2. generate per-player target hashes for each tier (never share raw
     answers between players)
  3. verify submitted answers by re-hashing, not by storing plaintext
  4. maintain the custom wordlist (500 base + injected player passwords)
  5. run the live leaderboard
  6. serve the finished wordlist at /luki once registration is closed

No shared terminal, no shared server-side cracking — each participant's
laptop does all the actual hashcat work. This app never breaks under load
because it never does the cracking itself.
"""
import hashlib
import os
import random
import sqlite3
import time
from functools import wraps

import bcrypt
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for, send_file

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "luki-admin")
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "crackme.db"))
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# How many of the strongest submitted passwords get pulled out of the
# wordlist entirely and reused as the Tier 5 (bcrypt) finale targets.
HOLDBACK_COUNT = 6

# Custom wordlist: new player passwords get inserted somewhere in this
# index range so they aren't sitting at a predictable spot.
INSERT_MIN, INSERT_MAX = 200, 300

TIERS = {
    1: {
        "name": "Meet hashcat",
        "concept": "Crack your own password with the exact command below. This is the whole custom wordlist — your password is hiding in it.",
        "algo": "md5",
        "source": "custom",
        "stars": 10,
    },
    2: {
        "name": "The wordlist matters",
        "concept": "Same command, same wordlist... but it won't work this time. This word isn't in the custom list — you'll need a bigger one.",
        "algo": "md5",
        "source": "rockyou",
        "stars": 15,
        "hint": "Your custom wordlist only has 500-ish words. rockyou.txt has millions. Try that instead.",
    },
    3: {
        "name": "Identify before you crack",
        "concept": "Your old command runs but finds nothing. Something about this hash is different — figure out what before you try again.",
        "algo": "sha256",
        "source": "seclists",
        "stars": 20,
        "hint": "Run `hashid target.hash` — the mode number you were using might not be right anymore.",
    },
    4: {
        "name": "What a salt does",
        "concept": "This one ships with an extra value alongside the hash. hashcat needs both to have any chance.",
        "algo": "sha256_salted",
        "source": "mixed",
        "stars": 25,
        "hint": "The file has `hash:salt`. Check the hashcat mode for salted SHA-256 and make sure you're passing the whole line, not just the hash.",
    },
    5: {
        "name": "Why some hashes survive",
        "concept": "This is a bcrypt hash. Run the same attack and watch the H/s counter — this is deliberately, and correctly, not meant to crack in the room.",
        "algo": "bcrypt",
        "source": "holdback_pool",
        "stars": 30,
        "hint": None,
    },
}
MAX_TIER = max(TIERS)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codename TEXT UNIQUE NOT NULL,
            plaintext_pending TEXT,
            strength_score REAL,
            finalized INTEGER DEFAULT 0,
            excluded_from_wordlist INTEGER DEFAULT 0,
            current_tier INTEGER DEFAULT 1,
            stars INTEGER DEFAULT 0,
            joined_at REAL
        );

        CREATE TABLE IF NOT EXISTS tier_targets (
            player_id INTEGER,
            tier INTEGER,
            target_hash TEXT,
            salt TEXT,
            solved_at REAL,
            hint_used INTEGER DEFAULT 0,
            PRIMARY KEY (player_id, tier)
        );

        CREATE TABLE IF NOT EXISTS tier_first_solver (
            tier INTEGER PRIMARY KEY,
            player_id INTEGER,
            solved_at REAL
        );

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def get_meta(key, default=None):
    row = get_db().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    db.commit()


def registration_closed():
    return get_meta("registration_closed", "0") == "1"


# ---------- hashing helpers ----------

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def sha256_salted(s, salt):
    return hashlib.sha256((s + salt).encode()).hexdigest()


def bcrypt_hash(s):
    return bcrypt.hashpw(s.encode(), bcrypt.gensalt(rounds=12)).decode()


def strength_score(pw):
    """Rough heuristic: length + charset diversity. Higher = stronger."""
    if not pw:
        return 0
    score = len(pw) * 2
    if any(c.islower() for c in pw):
        score += 2
    if any(c.isupper() for c in pw):
        score += 4
    if any(c.isdigit() for c in pw):
        score += 4
    if any(not c.isalnum() for c in pw):
        score += 8
    # predictable trailing patterns (word+digits+symbol) are still common
    # even when they "look" complex, so don't over-reward length alone
    return score


# ---------- wordlist sources ----------

def load_lines(filename):
    path = os.path.join(DATA_DIR, filename)
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def load_custom_wordlist():
    path = os.path.join(DATA_DIR, "custom_wordlist_live.txt")
    if not os.path.exists(path):
        base = load_lines("base_wordlist.txt")
        save_custom_wordlist(base)
        return base
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def save_custom_wordlist(words):
    path = os.path.join(DATA_DIR, "custom_wordlist_live.txt")
    with open(path, "w") as f:
        f.write("\n".join(words) + "\n")


def insert_into_custom_wordlist(word):
    """Insert one player's password directly between INSERT_MIN and
    INSERT_MAX in the current list. No shuffling — just a plain insert
    at a random spot in that band, exactly once, per player."""
    words = load_custom_wordlist()
    upper_bound = min(INSERT_MAX, len(words))
    lower_bound = min(INSERT_MIN, upper_bound)
    pos = random.randint(lower_bound, upper_bound)
    words.insert(pos, word)
    save_custom_wordlist(words)


_source_cache = {}
_used_words = {"rockyou": set(), "seclists": set(), "mixed": set()}


def _pool_for(source):
    if source not in _source_cache:
        if source == "rockyou":
            pool = load_lines("sample_rockyou.txt")
        elif source == "seclists":
            pool = load_lines("sample_seclists.txt")
        elif source == "mixed":
            pool = load_lines("sample_rockyou.txt") + load_lines("sample_seclists.txt")
        else:
            pool = []
        random.shuffle(pool)
        _source_cache[source] = pool
    return _source_cache[source]


def pick_unique_word(source):
    pool = _pool_for(source)
    used = _used_words.setdefault(source, set())
    for w in pool:
        if w not in used:
            used.add(w)
            return w
    # pool exhausted (shouldn't happen at workshop scale) — allow repeats
    return random.choice(pool)


# ---------- tier target generation ----------

def generate_tier_target(player_id, plaintext, tier):
    db = get_db()
    cfg = TIERS[tier]
    if tier == 1:
        target_hash = md5(plaintext)
        salt = None
    elif tier == 2:
        word = pick_unique_word("rockyou")
        target_hash = md5(word)
        salt = None
    elif tier == 3:
        word = pick_unique_word("seclists")
        target_hash = sha256(word)
        salt = None
    elif tier == 4:
        word = pick_unique_word("mixed")
        salt = os.urandom(4).hex()
        target_hash = sha256_salted(word, salt)
    elif tier == 5:
        # assigned later from the holdback pool, see finalize_registration()
        return
    else:
        raise ValueError("bad tier")

    db.execute(
        "INSERT INTO tier_targets (player_id, tier, target_hash, salt) VALUES (?, ?, ?, ?)",
        (player_id, tier, target_hash, salt),
    )
    db.commit()


def finalize_registration():
    """Called once, when Luki closes registration. Ranks all pending
    passwords by strength, holds back the strongest few as the Tier 5
    bcrypt pool (excluded from the wordlist entirely), generates every
    player's Tier 1-4 targets, and inserts everyone else's password into
    the shared custom wordlist."""
    db = get_db()
    load_custom_wordlist()  # make sure custom_wordlist_live.txt exists even if nobody ends up injected

    players = db.execute(
        "SELECT id, plaintext_pending, strength_score FROM players WHERE finalized=0"
    ).fetchall()

    ranked = sorted(players, key=lambda p: p["strength_score"], reverse=True)
    # Cap holdback so a tiny/test-sized room never excludes everyone —
    # at real workshop scale (30-50+ players) this is just HOLDBACK_COUNT.
    holdback_n = min(HOLDBACK_COUNT, max(0, len(players) - 1))
    holdback_ids = {p["id"] for p in ranked[:holdback_n]}
    holdback_plaintexts = [p["plaintext_pending"] for p in ranked[:holdback_n]]

    bcrypt_pool = [bcrypt_hash(pw) for pw in holdback_plaintexts] or [bcrypt_hash("Fallback$trongPass2025!")]
    set_meta("bcrypt_pool", "\x1f".join(bcrypt_pool))

    non_holdback_index = 0
    for p in players:
        pid, plaintext = p["id"], p["plaintext_pending"]
        excluded = pid in holdback_ids
        db.execute(
            "UPDATE players SET finalized=1, excluded_from_wordlist=? WHERE id=?",
            (1 if excluded else 0, pid),
        )
        generate_tier_target(pid, plaintext, 1)
        generate_tier_target(pid, plaintext, 2)
        generate_tier_target(pid, plaintext, 3)
        generate_tier_target(pid, plaintext, 4)

        pool = bcrypt_pool
        assigned_bcrypt = pool[non_holdback_index % len(pool)] if not excluded else pool[0]
        db.execute(
            "INSERT INTO tier_targets (player_id, tier, target_hash, salt) VALUES (?, 5, ?, NULL)",
            (pid, assigned_bcrypt),
        )
        if not excluded:
            insert_into_custom_wordlist(plaintext)
            non_holdback_index += 1

    db.commit()
    set_meta("registration_closed", "1")


# ---------- app ----------

app = Flask(__name__)
app.secret_key = APP_SECRET

# Self-healing: make sure the schema exists the moment this module is
# imported, regardless of whether a separate build-time init step ran.
# CREATE TABLE IF NOT EXISTS makes this safe to call on every import,
# including once per gunicorn worker.
init_db()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def current_player():
    pid = session.get("player_id")
    if not pid:
        return None
    return get_db().execute("SELECT * FROM players WHERE id=?", (pid,)).fetchone()


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    player = current_player()
    if player:
        return redirect(url_for("waiting") if not registration_closed() else url_for("play"))
    return render_template("join.html", closed=registration_closed())


@app.route("/join", methods=["POST"])
def join():
    if registration_closed():
        return render_template("join.html", closed=True, error=None)

    codename = request.form.get("codename", "").strip()
    password = request.form.get("password", "")
    if not codename or not password:
        return render_template("join.html", closed=False, error="Both fields are required.")

    db = get_db()
    existing = db.execute("SELECT id FROM players WHERE codename=?", (codename,)).fetchone()
    if existing:
        return render_template("join.html", closed=False, error="That codename is taken — pick another.")

    score = strength_score(password)
    cur = db.execute(
        "INSERT INTO players (codename, plaintext_pending, strength_score, joined_at) VALUES (?, ?, ?, ?)",
        (codename, password, score, time.time()),
    )
    db.commit()
    session["player_id"] = cur.lastrowid
    return redirect(url_for("waiting"))


@app.route("/waiting")
def waiting():
    player = current_player()
    if not player:
        return redirect(url_for("index"))
    if registration_closed():
        return redirect(url_for("play"))
    count = get_db().execute("SELECT COUNT(*) c FROM players").fetchone()["c"]
    return render_template("waiting.html", player=player, count=count)


@app.route("/play")
def play():
    player = current_player()
    if not player:
        return redirect(url_for("index"))
    if not registration_closed():
        return redirect(url_for("waiting"))

    tier = min(player["current_tier"], MAX_TIER)
    cfg = TIERS[tier]
    target = get_db().execute(
        "SELECT * FROM tier_targets WHERE player_id=? AND tier=?", (player["id"], tier)
    ).fetchone()

    finished = player["current_tier"] > MAX_TIER
    return render_template(
        "play.html",
        player=player,
        tier=tier,
        cfg=cfg,
        target=target,
        max_tier=MAX_TIER,
        finished=finished,
    )


@app.route("/submit-answer", methods=["POST"])
def submit_answer():
    player = current_player()
    if not player or not registration_closed():
        return redirect(url_for("index"))

    tier = min(player["current_tier"], MAX_TIER)
    cfg = TIERS[tier]
    answer = request.form.get("answer", "")
    db = get_db()
    target = db.execute(
        "SELECT * FROM tier_targets WHERE player_id=? AND tier=?", (player["id"], tier)
    ).fetchone()

    correct = False
    if cfg["algo"] == "md5":
        correct = md5(answer) == target["target_hash"]
    elif cfg["algo"] == "sha256":
        correct = sha256(answer) == target["target_hash"]
    elif cfg["algo"] == "sha256_salted":
        correct = sha256_salted(answer, target["salt"]) == target["target_hash"]
    elif cfg["algo"] == "bcrypt":
        try:
            correct = bcrypt.checkpw(answer.encode(), target["target_hash"].encode())
        except ValueError:
            correct = False

    if correct:
        now = time.time()
        db.execute(
            "UPDATE tier_targets SET solved_at=? WHERE player_id=? AND tier=?",
            (now, player["id"], tier),
        )
        first = db.execute("SELECT 1 FROM tier_first_solver WHERE tier=?", (tier,)).fetchone()
        bonus = 0
        if not first:
            db.execute(
                "INSERT INTO tier_first_solver (tier, player_id, solved_at) VALUES (?, ?, ?)",
                (tier, player["id"], now),
            )
            bonus = 10
        hint_penalty = 5 if target["hint_used"] else 0
        earned = max(cfg["stars"] + bonus - hint_penalty, 5)
        db.execute(
            "UPDATE players SET current_tier=?, stars=stars+? WHERE id=?",
            (tier + 1, earned, player["id"]),
        )
        db.commit()

    return redirect(url_for("play"))


@app.route("/use-hint", methods=["POST"])
def use_hint():
    player = current_player()
    if not player or not registration_closed():
        return redirect(url_for("index"))
    tier = min(player["current_tier"], MAX_TIER)
    db = get_db()
    db.execute(
        "UPDATE tier_targets SET hint_used=1 WHERE player_id=? AND tier=?",
        (player["id"], tier),
    )
    db.commit()
    return redirect(url_for("play"))


@app.route("/skip-tier5", methods=["POST"])
def skip_tier5():
    """Tier 5 (bcrypt) isn't meant to be cracked live — this lets a
    player mark it 'seen' and finish their run without waiting forever."""
    player = current_player()
    if not player:
        return redirect(url_for("index"))
    db = get_db()
    db.execute(
        "UPDATE players SET current_tier=?, stars=stars+5 WHERE id=?",
        (MAX_TIER + 1, player["id"]),
    )
    db.commit()
    return redirect(url_for("play"))


@app.route("/leaderboard")
def leaderboard():
    db = get_db()
    players = db.execute(
        "SELECT codename, current_tier, stars FROM players WHERE finalized=1 ORDER BY current_tier DESC, stars DESC"
    ).fetchall()
    first_solvers = db.execute(
        """SELECT tier_first_solver.tier, players.codename
           FROM tier_first_solver JOIN players ON players.id = tier_first_solver.player_id
           ORDER BY tier_first_solver.tier"""
    ).fetchall()
    return render_template(
        "leaderboard.html",
        players=players,
        first_solvers=first_solvers,
        max_tier=MAX_TIER,
        closed=registration_closed(),
    )


@app.route("/leaderboard/data")
def leaderboard_data():
    db = get_db()
    players = db.execute(
        "SELECT codename, current_tier, stars FROM players WHERE finalized=1 ORDER BY current_tier DESC, stars DESC"
    ).fetchall()
    return jsonify([dict(p) for p in players])


# ---------- admin ----------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_panel"))
        error = "Wrong password."
    return render_template("admin_login.html", error=error)


@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    count = db.execute("SELECT COUNT(*) c FROM players").fetchone()["c"]
    return render_template("admin.html", count=count, closed=registration_closed())


@app.route("/admin/close-registration", methods=["POST"])
@admin_required
def admin_close_registration():
    if not registration_closed():
        finalize_registration()
    return redirect(url_for("admin_panel"))


@app.route("/luki")
def luki_download():
    # Intentionally unauthenticated — low-stakes club event, not a
    # guessable-by-outsiders concern for this use case.
    if not registration_closed():
        return "Wordlist isn't ready yet — registration is still open.", 400
    path = os.path.join(DATA_DIR, "custom_wordlist_live.txt")
    return send_file(path, as_attachment=True, download_name="securinets_custom_wordlist.txt")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
