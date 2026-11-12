"""
WSGI config for securITquiz project.

It exposes the WSGI callable as a module-level variable named ``application``.
For Vercel deployment, it also exposes ``app = application`` and handles
safe ephemeral SQLite database initialization in /tmp.
"""

import os
import sys
import shutil
import logging
import contextlib
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Ensure securITquiz project directory is on sys.path
_sub_project = Path(__file__).resolve().parent
if not (_sub_project / 'manage.py').exists():
    _sub_project = _sub_project.parent

if str(_sub_project) not in sys.path:
    sys.path.insert(0, str(_sub_project))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securITquiz.settings')

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
app = application

_init_thread_lock = threading.Lock()


@contextlib.contextmanager
def _database_initialization_lock(lock_path, timeout=30.0):
    """
    Context manager providing cross-process and cross-thread synchronization
    to prevent concurrent database copy or migration races in serverless runtimes.
    Guarantees lock release even if initialization fails or raises an exception.
    """
    acquired_thread = _init_thread_lock.acquire(timeout=timeout)
    if not acquired_thread:
        raise TimeoutError(f"Timed out after {timeout}s waiting for local thread initialization lock.")

    lock_file = None
    try:
        lock_path = Path(lock_path)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(lock_path, 'a+')

        start_time = time.time()
        while True:
            try:
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except ImportError:
                    import msvcrt
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except (BlockingIOError, OSError):
                if time.time() - start_time >= timeout:
                    raise TimeoutError(
                        f"Timed out after {timeout}s waiting for database initialization lock on {lock_path}."
                    )
                time.sleep(0.05)

        yield
    finally:
        if lock_file is not None:
            try:
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    import msvcrt
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
            finally:
                try:
                    lock_file.close()
                except Exception:
                    pass
        _init_thread_lock.release()


def _is_db_ready(db_path):
    """
    Verifies that the SQLite database file exists, is non-empty, passes integrity
    checks, contains all essential core/application tables and default roles,
    and has all required Django and quiz application migrations applied.
    """
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    conn = None
    try:
        import sqlite3
        conn = sqlite3.connect(str(db_path), timeout=2)
        cur = conn.cursor()

        # 1. Database integrity check (detects corrupt or partial SQLite files)
        cur.execute("PRAGMA quick_check;")
        check_row = cur.fetchone()
        if not check_row or check_row[0] != 'ok':
            return False

        # 2. Verify django_migrations and core/application tables are present
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
            "'django_session', 'auth_group', 'auth_user', 'django_migrations', "
            "'quiz_quiz', 'quiz_question', 'quiz_quizsubmission', 'quiz_activesession'"
            ");"
        )
        tables = {row[0] for row in cur.fetchall()}
        required_tables = {
            'django_session', 'auth_group', 'auth_user', 'django_migrations',
            'quiz_quiz', 'quiz_question', 'quiz_quizsubmission', 'quiz_activesession'
        }
        if not required_tables.issubset(tables):
            return False

        # 3. Read applied migrations recorded in database
        cur.execute("SELECT app, name FROM django_migrations;")
        applied = {(row[0], row[1]) for row in cur.fetchall()}

       # 4. Verify all default roles are present in auth_group
        cur.execute(
            """
            SELECT name FROM auth_group
            WHERE name IN ('Student', 'Instructor', 'Administrator');
            """
        )

        roles = {row[0] for row in cur.fetchall()}

        if not {'Student', 'Instructor', 'Administrator'}.issubset(roles):
            return False

        # 5. Discover all disk migrations across Django core and quiz application
        from django.db.migrations.loader import MigrationLoader
        loader = MigrationLoader(None, ignore_no_migrations=True)
        required = set(loader.disk_migrations.keys())

        # Verify all required disk migrations are recorded as applied
        if not required or not required.issubset(applied):
            return False

        # Explicitly verify quiz application migrations are present and applied
        quiz_required = {m for m in required if m[0] == 'quiz'}
        if not quiz_required or not quiz_required.issubset(applied):
            return False

        return True
    except Exception as exc:
        logger.warning("Database readiness check failed: %s", exc)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def ensure_serverless_database():
    """
    Ensures that the SQLite database is populated and fully migrated when deployed
    to a serverless platform like Vercel where the application code resides on a
    read-only filesystem (/var/task) and runtime SQLite read-write storage resides in /tmp.

    Concurrency and safety guarantees:
    - Runs only when IS_SERVERLESS is True (preserves local development).
    - Checks complete migration and schema readiness via _is_db_ready.
    - Uses double-checked locking with an advisory file & thread lock to prevent concurrent races.
    - Ensures the lock is unconditionally released even if initialization fails.
    - Preserves existing /tmp SQLite setup and atomic replacement (os.replace) during bundled DB copy.
    - If migrations or roles are missing, automatically executes them before handling requests.
    - Closes open connections before file replacements and migration execution.
    - Does not silently swallow setup_roles or migration failures; raises RuntimeError on failure.
    """
    from django.conf import settings
    from django.db import connections

    if not getattr(settings, 'IS_SERVERLESS', False):
        return

    default_db = settings.DATABASES.get('default', {})
    if default_db.get('ENGINE') != 'django.db.backends.sqlite3':
        logger.info(
            "Configured database engine is '%s'; skipping serverless SQLite initialization.",
            default_db.get('ENGINE'),
        )
        return

    db_path = Path(default_db.get('NAME', ''))

    # Fast path: skip locking if database is already fully initialized and ready
    if _is_db_ready(db_path):
        return

    lock_path = db_path.parent / f"{db_path.name}.init.lock"

    with _database_initialization_lock(lock_path):
        # Double-checked locking: check readiness again after acquiring lock
        if _is_db_ready(db_path):
            return

        db_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Attempt atomic copy of bundled pre-populated db.sqlite3 template if available
        bundled_db = settings.BASE_DIR / 'db.sqlite3'
        if bundled_db.resolve() != db_path.resolve() and bundled_db.exists() and bundled_db.stat().st_size > 0:
            try:
                connections.close_all()
                temp_copy = db_path.with_name(f"{db_path.name}.tmp.{os.getpid()}")
                shutil.copy2(bundled_db, temp_copy)
                os.replace(temp_copy, db_path)
                connections.close_all()
                if _is_db_ready(db_path):
                    return
            except Exception as e:
                logger.warning("Could not copy bundled database to /tmp: %s", e)

        # 2. If no bundled DB, copy failed, or migrations/roles are missing, execute migrations and setup default roles
        try:
            connections.close_all()
            from django.core.management import call_command
            call_command('migrate', interactive=False, verbosity=0)

            # Explicitly execute default role creation; do NOT silently treat failures as success
            call_command('setup_roles')

            if not _is_db_ready(db_path):
                raise RuntimeError("Database verification failed: unapplied migrations or missing schema/roles remain after initialization.")
        except Exception as exc:
            logger.critical("Critical serverless database initialization failure: %s", exc, exc_info=True)
            raise RuntimeError(f"Critical serverless database initialization failure: {exc}") from exc
        finally:
            connections.close_all()


# Initialize database in serverless runtime
ensure_serverless_database()
