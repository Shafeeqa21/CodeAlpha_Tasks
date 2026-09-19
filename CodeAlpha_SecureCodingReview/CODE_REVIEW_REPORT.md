# Secure Coding Review Report
**CodeAlpha Internship – Task 3: Secure Coding Review**

**Application:** Python Login/Signup Authentication System
**Language:** Python 3
**Files reviewed:** `vulnerable_app.py` (before) → `secure_app.py` (after)
**Static analyzer used:** [Bandit](https://bandit.readthedocs.io/) v1.9.4 (industry-standard Python SAST tool)
**Method:** Automated static analysis (Bandit) + manual line-by-line code inspection

---

## 1. Summary

| Metric | Before | After |
|---|---|---|
| Bandit issues found | 5 (1 High, 3 Medium, 1 Low) | **0** |
| SQL Injection points | 3 | 0 |
| Weak/unsalted hashing | Yes (MD5) | No (salted PBKDF2 via Werkzeug) |
| Hardcoded credentials | Yes | No |
| Input validation | None | Username + password strength rules |
| Username enumeration | Possible | Prevented |

---

## 2. Findings

### Finding 1 — Weak Password Hashing (MD5, No Salt)
- **Severity:** High | **CWE-327**
- **Location:** `hash_password()`, line 33
- **Issue:** Passwords are hashed with MD5, a cryptographically broken, fast hash with no salt. Attackers can crack MD5 hashes with rainbow tables in seconds, and identical passwords produce identical hashes across users.
- **Recommendation:** Use a slow, salted hashing algorithm designed for passwords (PBKDF2, bcrypt, scrypt, or Argon2).
- **Fix applied:** Replaced with `werkzeug.security.generate_password_hash()` / `check_password_hash()`, which uses salted PBKDF2 internally.

### Finding 2 — SQL Injection (3 instances)
- **Severity:** Medium–High | **CWE-89**
- **Location:** `signup()` line 43, `login()` line 58, error-check block line 69
- **Issue:** User input (`username`, `password`) is inserted directly into SQL strings via `%` formatting and f-strings. An attacker could submit a username like `' OR '1'='1` to bypass authentication or corrupt the database.
- **Recommendation:** Always use parameterized queries; never build SQL with string interpolation.
- **Fix applied:** All queries rewritten with `?` placeholders and a separate parameters tuple, e.g. `cur.execute("SELECT ... WHERE username = ?", (username,))`.

### Finding 3 — Verbose Errors Enable Username Enumeration
- **Severity:** Medium | **CWE-203**
- **Location:** `login()`, lines 66–71
- **Issue:** The app tells the user separately whether the *username* was wrong or the *password* was wrong. This lets an attacker enumerate valid usernames by observing which error they get.
- **Recommendation:** Return one generic message ("Invalid username or password") regardless of which part was wrong.
- **Fix applied:** `secure_app.py` returns a single generic error in both cases.

### Finding 4 — Hardcoded Credentials
- **Severity:** Low–Medium | **CWE-798**
- **Location:** `ADMIN_USER` / `ADMIN_PASSWORD`, lines 78–79
- **Issue:** An admin username and plaintext password are hardcoded directly in source code. Anyone with source access (or a leaked repo) gets instant admin access.
- **Recommendation:** Never hardcode credentials. Store admin accounts in the database like any other user, or load secrets from environment variables / a secrets manager.
- **Fix applied:** Removed the hardcoded admin block entirely; admin is a regular DB-backed account.

### Finding 5 — No Input Validation
- **Severity:** Low–Medium | **CWE-20**
- **Location:** `main()`, whole signup/login flow
- **Issue:** Usernames and passwords are accepted with no length, character, or strength checks, and duplicate usernames are allowed (no `UNIQUE` constraint).
- **Recommendation:** Validate format (allowed characters, length) and enforce a minimum password strength policy; add a `UNIQUE` constraint on username.
- **Fix applied:** Added regex-based username validation, a password strength check (8+ chars, upper/lower/digit), and a `UNIQUE NOT NULL` constraint on the `username` column.

### Finding 6 — Passwords Echoed in Terminal
- **Severity:** Low | **CWE-549**
- **Location:** `input("Password: ")` calls throughout
- **Issue:** Using plain `input()` for passwords shows them on screen as the user types (shoulder-surfing risk) and may be captured in terminal history/logs.
- **Recommendation:** Use `getpass.getpass()` to mask password entry.
- **Fix applied:** `secure_app.py` uses `getpass.getpass()` instead of `input()` for all password prompts.

---

## 3. Static Analysis Output (Bandit)

**Before (`vulnerable_app.py`):**
```
Total issues: 5  (High: 1, Medium: 3, Low: 1)
- B324: Weak MD5 hash used for security     [High]
- B608: SQL injection (signup query)        [Medium]
- B608: SQL injection (login query)         [Medium]
- B608: SQL injection (error-check query)   [Medium]
- B105: Hardcoded password string           [Low]
```

**After (`secure_app.py`):**
```
No issues identified.
```

---

## 4. General Secure Coding Recommendations

1. **Never trust user input** — validate and sanitize on every entry point.
2. **Use parameterized queries / ORM** for all database access; never concatenate or format SQL strings.
3. **Hash passwords with a purpose-built algorithm** (bcrypt/Argon2/PBKDF2) — never MD5/SHA1 alone.
4. **Keep secrets out of source code** — use environment variables or a secrets manager, and add config files to `.gitignore`.
5. **Fail generically** on authentication errors to avoid leaking account existence.
6. **Add rate limiting / account lockout** on login endpoints to slow brute-force attempts (not yet implemented in `secure_app.py` — noted as a future improvement).
7. **Run a static analyzer (Bandit, Semgrep, etc.) in CI** on every commit so regressions are caught automatically.

---

## 5. Remediation Status

| Finding | Status |
|---|---|
| 1. Weak hashing | ✅ Fixed |
| 2. SQL Injection | ✅ Fixed |
| 3. Username enumeration | ✅ Fixed |
| 4. Hardcoded credentials | ✅ Fixed |
| 5. No input validation | ✅ Fixed |
| 6. Password echoed in terminal | ✅ Fixed |
| 7. No rate limiting / lockout | ⚠️ Not implemented — recommended for production |

---

*Reviewed as part of CodeAlpha Cyber Security Internship — Task 3.*