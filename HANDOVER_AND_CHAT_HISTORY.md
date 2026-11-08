# Class Test Portal (`securITquiz`) - Complete Chat Archive & Handover Guide

> **Note for New Machine Setup**: This document contains the full archive, architecture decisions, implementation details, bug fixes, test results, and handover instructions from the development session conducted on November 9, 2026. Keep this file in the repository so you can reference it on any computer.

---

## 1. Project Overview & Repository State

- **GitHub Repository**: [`https://github.com/SamVillanueva1215/securITquiz`](https://github.com/SamVillanueva1215/securITquiz)
- **Active Feature Branch**: [`feature-final-NoDesign`](https://github.com/SamVillanueva1215/securITquiz/tree/feature-final-NoDesign)
- **Latest Commit**: `5122fd1` - `feat: Complete mutual two-device authorization, DSA verification, session management, and notification system`
- **Primary Framework**: Django 6.1.2 on Python 3.13.9
- **Database Engine**: SQLite (`securITquiz/db.sqlite3` with Django ORM)
- **Cryptographic Engine**: PyCryptodome DSA (FIPS 186-3 finite-field with SHA-256)
- **Test Suite Status**: **88 of 88 automated unit and integration tests passing (100% PASS)**

---

## 2. Conversation & Development Summary (Chat History)

### Phase 1: Context Inspection & Baseline Discovery
- **User Prompt**: The user provided the "MASTER DEVELOPMENT PROMPT" to continue interrupted development of the Class Test Portal without breaking existing features.
- **Project Structure Discovery**:
  - Found repository root: `C:\Users\JUSTINE\OneDrive\เอกสาร\QUIZ`
  - Found active application folder: `C:\Users\JUSTINE\OneDrive\เอกสาร\QUIZ\securITquiz`
  - Discovered pre-existing 82 tests passing in `securITquiz/quiz/tests.py`.
- **Status Classification Checklist Created**: Evaluated all requirements across RBAC, DSA, 2-Device Auth, Session Timeout, Database, Notifications, and Security.

### Phase 2: Implementation of Incomplete Requirements
1. **Email & Notification Integration (Part 6)**:
   - Implemented 4 dedicated functions in [`securITquiz/quiz/notifications.py`](securITquiz/quiz/notifications.py):
     - `notify_device_auth_requested(user, requesting_ip, expires_at)`
     - `notify_device_auth_approved(user, requesting_ip, approver_ip)`
     - `notify_device_auth_denied(user, requesting_ip, denier_ip)`
     - `notify_device_auth_expired(user, requesting_ip)`
   - Verified all 9 notification scenarios format and dispatch safely via `send_safe_email` with console/SMTP fallback.
2. **Server-Issued Device Identification (`device_id`) (Part 3.6 & Part 5)**:
   - Added `get_or_create_device_id` in [`securITquiz/quiz/middleware.py`](securITquiz/quiz/middleware.py) to issue a persistent, secure `securit_device_id` cookie (HttpOnly, SameSite=Lax).
   - Added `device_id` field to `ActiveSession`, `DeviceAuthorizationRequest` (`requesting_device_id`, `authorized_device_id`), and `AuditLog`.
   - Created and applied migration `0007_activesession_device_id_auditlog_device_id_and_more.py`.
3. **Audit Logging Complete Coverage (Part 4.4)**:
   - Expanded `AuditLog.ACTION_CHOICES` and hooked up explicit event logging for:
     - `SESSION_CREATED`
     - `SESSION_EXPIRED`
     - `SESSION_REVOKED`
     - `SESSION_LOGOUT`
     - `LOGIN_SUCCESS` / `LOGIN_FAILED`
     - `DEVICE_AUTHORIZATION_REQUESTED`
     - `DEVICE_AUTHORIZATION_APPROVED`
     - `DEVICE_AUTHORIZATION_DENIED`
     - `DEVICE_AUTHORIZATION_EXPIRED`
     - `DEVICE_AUTHORIZATION_TRANSFERRED`
4. **Three-State DSA Status Classification (Part 2.4)**:
   - Resolved false tamper alerts on legacy unsigned submissions.
   - Distinguished records as:
     - `✓ DSA Verified`: Intact cryptographic signature matching hash.
     - `⚠️ Compromised / Tampered`: Invalid signature or altered answers/scores.
     - `⚪ Unsigned / Legacy Record`: Missing or blank signature (does not raise false tamper alerts).
   - Updated views and badges in `instructor_quiz_results.html`, `instructor_submission_detail.html`, and CSV exports.
5. **Cookie Security Hardening (Part 4.5 & Part 10)**:
   - Configured `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, `CSRF_COOKIE_SAMESITE = 'Lax'`, and conditional production HTTPS settings.
   - Added `X_FRAME_OPTIONS = 'DENY'` and `SECURE_CONTENT_TYPE_NOSNIFF = True`.
   - Updated `.gitignore` to prevent committing `.pem`, `.key`, or `.backup*` files.

### Phase 3: Diagnostics on Server Launch Issue
- **User Issue**: "launch application server failed to load page"
- **Diagnosis**:
  1. `python` was not in Windows PATH (only `py` launcher was available). Fixed by adding `C:\Program Files\Python313` and `C:\Program Files\Python313\Scripts` to User PATH.
  2. Running `manage.py runserver` from root directory previously executed an unconfigured skeleton from an early Git commit (`ALLOWED_HOSTS = []` and missing `/login/` routes).
- **Resolution**:
  - Updated root [`manage.py`](manage.py) to automatically detect `securITquiz` subproject context and switch working directory/sys.path.
  - Verified live HTTP 200 responses on `/`, `/login/`, and `/register/`.

### Phase 4: Git Push to Target Branch
- Switched to and committed changes on branch `feature-final-NoDesign`.
- Successfully pushed commit `5122fd1` to `origin/feature-final-NoDesign`.

---

## 3. How to Set Up and Run on a New Computer

When you move to a new computer, follow these exact steps:

### Step 1: Install Python 3.13
1. Download and install **Python 3.13** from [python.org](https://www.python.org/).
2. **Important**: Check the box **"Add Python to PATH"** during installation.
3. Verify in your terminal:
   ```powershell
   python --version
   ```

### Step 2: Clone the Repository & Checkout Branch
```powershell
git clone https://github.com/SamVillanueva1215/securITquiz.git
cd securITquiz
git checkout feature-final-NoDesign
```

### Step 3: Install Required Dependencies
Run:
```powershell
pip install django argon2-cffi pycryptodome cryptography
```

### Step 4: Run Migrations & Setup Roles
From the project folder (`securITquiz` or repository root):
```powershell
python manage.py migrate
python manage.py setup_roles
```

### Step 5: (Optional) Create an Instructor Account
```powershell
python manage.py create_instructor --username prof_admin --email admin@university.edu
```

### Step 6: Run the Automated Test Suite (Verify Everything Works)
```powershell
python manage.py test quiz
```
*(Expected output: `Ran 88 tests in ... OK`)*

### Step 7: Launch the Server
```powershell
python manage.py runserver 127.0.0.1:8000
```
Then open your browser to:
- **Home**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Login**: [http://127.0.0.1:8000/login/](http://127.0.0.1:8000/login/)
- **Register**: [http://127.0.0.1:8000/register/](http://127.0.0.1:8000/register/)

---

## 4. Key Architectural & Security Reference

### Account Roles & Routing
| Role | Landing Dashboard | Authorized Actions |
|---|---|---|
| **Student** | `/student/` | Take quizzes with PIN, view released results, view profile. |
| **Instructor** | `/instructor/` | Create/edit quizzes, toggle status/results, inspect DSA submissions, export CSV, view security audit logs. |

### Mutual Two-Device Authorization Flow
1. **Device A** is logged in and actively browsing.
2. **Device B** attempts to log in with the same account.
3. **Device B** is kept in an unauthenticated pending state and redirected to `/login/waiting-approval/` with a 60-second countdown.
4. **Device A** receives an on-screen popup modal in `base.html` showing Device B's IP and countdown.
5. If **Device A clicks Approve**:
   - Device B is authenticated and redirected to dashboard.
   - Device A's session is terminated immediately.
   - `DEVICE_AUTHORIZATION_APPROVED` and `DEVICE_AUTHORIZATION_TRANSFERRED` are logged.
6. If **Device A clicks Deny** or **60 seconds expire**:
   - Device B is rejected with an on-screen explanation.
   - Device A retains full active authorization.

### Cryptographic Non-Repudiation (DSA FIPS 186-3)
- Submissions are signed on backend before DB commit using finite-field DSA with SHA-256.
- Version 2 payload includes: `v2|student:{username}|quiz:{quiz_id}|score:{score}|percentage:{percentage:.2f}|answers:{canonical_json}|time:{iso_timestamp}`.
- Private key resides on server in `dsa_private_key.pem`; public key exported to `dsa_public_key.pem`.
- On record review, public key verifies mathematically that student ID, quiz ID, score, timestamp, and submitted answers were not modified after submission.

### Inactivity & Session Protection
- Inactivity window: **Strict 5 minutes** enforced on backend via [`SingleActiveSessionMiddleware`](securITquiz/quiz/middleware.py).
- Expired sessions are purged from `ActiveSession` and Django `Session` table, and logged as `SESSION_EXPIRED`.
