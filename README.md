# Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

## 1. Description of the project and API

This project is a secure REST API built with **Python (Flask)**. It implements core security protections against OWASP Top 10 vulnerabilities (SQLi, XSS, Broken Authentication). The project also integrates **GitHub Actions** for automated CI/CD security scanning (SAST & SCA). Additionally, it includes a comprehensive analysis, reproduction, and remediation of a real-world vulnerability (Server-Side Template Injection) using **Vulhub**.

### API Endpoints

1. **`POST /auth/register`** (Custom Third Endpoint)
   - **Description**: Registers a new user. Passwords are securely hashed using `bcrypt` before being stored in the SQLite database.
   - **Example (PowerShell)**:
     ```powershell
     Invoke-RestMethod -Uri "http://localhost:5000/auth/register" -Method Post -ContentType "application/json" -Body '{"login":"alice","password":"pass123"}'
     ```

2. **`POST /auth/login`**
   - **Description**: Authenticates the user. If successful, returns a valid JSON Web Token (JWT).
   - **Example (PowerShell)**:
     ```powershell
     Invoke-RestMethod -Uri "http://localhost:5000/auth/login" -Method Post -ContentType "application/json" -Body '{"login":"alice","password":"pass123"}'
     ```

3. **`GET /api/data`**
   - **Description**: Retrieves protected data (user list). Access is strictly restricted to authenticated users with a valid JWT.
   - **Example (PowerShell)**:
     ```powershell
     Invoke-RestMethod -Uri "http://localhost:5000/api/data" -Method Get -Headers @{"Authorization"="Bearer <your_jwt_token>"}
     ```

---

## 2. Detailed description of implemented security measures

### Protection against SQL Injection (SQLi)

The application strictly uses **Parameterized Queries (Prepared Statements)** via `sqlite3`. No string concatenation or formatting is used to construct SQL queries. User inputs are passed as parameters to the database driver, ensuring that malicious inputs (e.g., `' OR 1=1 --`) are treated as plain data and not executable code.

### Protection against Cross-Site Scripting (XSS)

All user-controlled data returned in API responses is sanitized and escaped using `markupsafe.escape()`. This prevents malicious scripts (e.g., `<script>alert(1)</script>`) from being executed in the client's browser.

### Protection against Broken Authentication

- **Password Hashing**: Plaintext passwords are never stored. The `bcrypt` algorithm is used to hash passwords with a unique salt.
- **JWT Authentication**: Upon successful login, the server issues a JWT (JSON Web Token) with an expiration time.
- **Middleware Verification**: A custom decorator/middleware is implemented to intercept requests to protected endpoints. It verifies the `Authorization: Bearer <token>` header. If the token is missing, invalid, or expired, the server rejects the request with `401 Unauthorized`.

**API & Security Testing Evidence:**

*(Note: Screenshots demonstrate JWT issuance, access without token being denied, and access with a valid token being granted.)*

![API Testing - JWT Auth](./screenshots/api_auth_test.png)

---

## 3. CI/CD Security Scans

A CI/CD pipeline is configured in `.github/workflows/ci.yml`. It automatically runs on every `push` and `pull_request` to the `main` branch.

- **SAST (Static Application Security Testing)**: Uses **Bandit** to scan the Python source code for common security flaws (e.g., hardcoded secrets, insecure use of libraries).
- **SCA (Software Composition Analysis)**: Uses **Safety** to check the `requirements.txt` against a database of known vulnerabilities in third-party dependencies.

**CI/CD Pipeline Evidence:**

![GitHub Actions Pipeline](./screenshots/ci_pipeline.png)

![SAST and SCA Scan Results](./screenshots/ci_scan_results.png)

---

## 4. Vulnerability Analysis (Vulhub: Flask SSTI)

### Vulnerability Name & Description

**Server-Side Template Injection (SSTI) in Flask (Vulhub `flask/ssti` environment)**

*(Note: Since `flask/CVE-2018-1000656` was removed from the official Vulhub repository, we use the actively maintained `flask/ssti` environment to fulfill the CVE analysis requirement. SSTI can lead to full Remote Code Execution (RCE), representing a critical vulnerability).*

### Sequence of Actions to Reproduce the Vulnerability

1. Navigate to the environment and start the vulnerable container:
   ```bash
   cd vulhub/flask/ssti
   docker compose up -d
   ```

2. Verify the template injection. Access the vulnerable endpoint with the payload `{{233*233}}`:
   ```bash
   curl -g "http://localhost:8000/?name={{233*233}}"
   ```
   **Result**: The server returns `Hello 54289`, proving that the mathematical expression was executed by the Jinja2 engine.

3. Escalate to Remote Code Execution (RCE). Inject a payload using the `__builtins__` chain to execute the `id` command:
   ```bash
   curl -g "http://localhost:8000/?name={{config.__class__.__init__.__globals__['__builtins__'].__import__('os').popen('id').read()}}"
   ```
   **Result**: The server returns the system output (e.g., `uid=33(www-data)...`), confirming RCE.

**Reproduction Evidence:**

![SSTI Reproduce - 54289](./screenshots/ssti_repro_math.png)

![SSTI Reproduce - Command Execution](./screenshots/ssti_repro_rce.png)

### Root Cause Analysis

The vulnerability is caused by a fundamental logic error: **failing to separate user data from executable code**.

In the vulnerable source code `Template("Hello " + name)`, the user input (`name` parameter) is concatenated directly into the template source code. When the Jinja2 engine renders the template, it treats the `{{ }}` syntax injected by the attacker as valid template logic. By exploiting Python's object inheritance and global variables (e.g., `__class__`, `__globals__`), the attacker can break out of the template context and execute arbitrary system commands.

### Description of the Applied Fix

**What was changed:** The vulnerable string concatenation was removed. The code was modified to pass the user input as a **template variable** rather than a part of the template source.

```python
# Fixed code:
return render_template_string("Hello {{ name }}", name=name)
```

**Why it is effective:** By using `render_template_string` with keyword arguments (`name=name`), the Jinja2 engine treats `name` purely as a data variable. Even if the user input contains Jinja2 syntax (like `{{233*233}}`), it will be rendered as a literal string and will not be evaluated as executable code.

### Proof of Vulnerability Elimination

After applying the fix and rebuilding the container (`docker compose down && docker compose up --build -d`), the attack was re-executed:

1. **Math payload (`{{233*233}}`)**: The server now returns the literal text `Hello {{233*233}}`. The expression is no longer evaluated.
2. **RCE payload**: The command execution fails, returning the raw literal string.
3. **Regression Test**: Normal functionality remains intact. Requesting `?name=Alice` correctly returns `Hello Alice`.

**Fix Verification Evidence:**

![SSTI Fixed - Attack Failed](./screenshots/ssti_fixed.png)

---

## 5. Project Links

- **Public Git Repository**: [https://github.com/11A18633-9318-4EAD-A762-3E838CE7CF1A/secure-api-lab](https://github.com/11A18633-9318-4EAD-A762-3E838CE7CF1A/secure-api-lab)
- **Last Successful Pipeline Run**: [Click here to view Actions](https://github.com/11A18633-9318-4EAD-A762-3E838CE7CF1A/secure-api-lab/actions)

## 6. Fixes Folder

The `fixes/` directory in this repository contains the remediated source code (`fixed_app.py`) for the Vulhub SSTI environment, demonstrating the exact code changes applied to resolve the vulnerability.
