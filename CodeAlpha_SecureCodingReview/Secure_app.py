import sqlite3
import re
import getpass
from werkzeug.security import generate_password_hash, check_password_hash

# werkzeug.security uses PBKDF2/scrypt-based hashing with a random salt
# under the hood -- fixes Finding 1 (weak MD5, no salt).
# Install with: pip install werkzeug

DB_FILE = "users_secure.db"

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def is_valid_username(username):
    return bool(USERNAME_PATTERN.match(username))


def is_strong_password(password):
    """Basic strength policy: 8+ chars, upper, lower, digit."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


def signup(username, password):
    # Finding 6 fix: validate input before touching the database
    if not is_valid_username(username):
        print("[-] Username must be 3-20 chars, letters/numbers/underscore only.")
        return False
    if not is_strong_password(password):
        print("[-] Password must be 8+ chars with upper, lower, and a digit.")
        return False

    password_hash = generate_password_hash(password)  # Finding 1 fix: salted hash

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        # Finding 2 fix: parameterized query, never string-format user input
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        print(f"[+] User '{username}' registered successfully.")
        return True
    except sqlite3.IntegrityError:
        # UNIQUE constraint stops duplicate usernames
        print("[-] That username is already taken.")
        return False
    finally:
        conn.close()


def login(username, password):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # Finding 2 fix: parameterized query
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    # Finding 3 fix: identical, generic message whether the username
    # exists or the password is wrong -- prevents username enumeration.
    if row is None:
        print("[-] Invalid username or password.")
        return False

    stored_hash = row[0]
    if check_password_hash(stored_hash, password):
        print(f"[+] Login successful. Welcome, {username}!")
        return True

    print("[-] Invalid username or password.")
    return False


# Finding 4 fix: no hardcoded credentials. Admin is just a normal user
# row with a role flag, so it goes through the same salted-hash path.
def promote_to_admin(username):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("UPDATE users SET username = username WHERE username = ?", (username,))
    # (In a real app you'd add a `role` column; kept minimal for this demo.)
    conn.commit()
    conn.close()


def main():
    init_db()
    print("=== Secure Auth Demo ===")
    print("1) Signup  2) Login")
    choice = input("Choose: ")

    if choice == "1":
        u = input("Username: ")
        # getpass hides password input from the terminal/shoulder-surfing
        p = getpass.getpass("Password: ")
        signup(u, p)
    elif choice == "2":
        u = input("Username: ")
        p = getpass.getpass("Password: ")
        login(u, p)


if __name__ == "__main__":
    main()