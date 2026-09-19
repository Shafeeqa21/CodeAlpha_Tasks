import sqlite3
import hashlib

DB_FILE = "users.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


# --- VULNERABILITY 1: Weak hashing (MD5) with no salt ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def signup(username, password):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    hashed = hash_password(password)

    # --- VULNERABILITY 2: SQL Injection (string formatting into query) ---
    query = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, hashed)
    cur.execute(query)

    conn.commit()
    conn.close()
    print(f"[+] User '{username}' registered successfully.")


def login(username, password):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    hashed = hash_password(password)

    # --- VULNERABILITY 2 (again): SQL Injection via f-string ---
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
    cur.execute(query)
    result = cur.fetchone()
    conn.close()

    if result:
        print(f"[+] Login successful. Welcome, {username}!")
        return True
    else:
        # --- VULNERABILITY 3: Verbose error leaks whether username exists ---
        cur2 = sqlite3.connect(DB_FILE).cursor()
        cur2.execute(f"SELECT * FROM users WHERE username = '{username}'")
        if cur2.fetchone():
            print("[-] Login failed: incorrect password.")
        else:
            print("[-] Login failed: username does not exist.")
        return False


# --- VULNERABILITY 4: Hardcoded credentials / secret ---
ADMIN_USER = "admin"
ADMIN_PASSWORD = "SuperSecret123"  # hardcoded plaintext admin password


def admin_login(username, password):
    # --- VULNERABILITY 5: Plaintext comparison, no rate limiting / lockout ---
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        print("[+] Admin access granted.")
        return True
    print("[-] Admin access denied.")
    return False


# --- VULNERABILITY 6: No input validation at all ---
def main():
    init_db()
    print("=== Vulnerable Auth Demo ===")
    print("1) Signup  2) Login  3) Admin Login")
    choice = input("Choose: ")

    if choice == "1":
        u = input("Username: ")
        p = input("Password: ")
        signup(u, p)  # no length/format checks, no duplicate-username check
    elif choice == "2":
        u = input("Username: ")
        p = input("Password: ")
        login(u, p)
    elif choice == "3":
        u = input("Admin username: ")
        p = input("Admin password: ")
        admin_login(u, p)


if __name__ == "__main__":
    main()