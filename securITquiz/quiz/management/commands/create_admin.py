import getpass
import sys
import warnings

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email
from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.password_validation import validate_password
from django.db import connection, transaction

from quiz.models import AuditLog


ADMIN_SCOPED_PERMISSIONS = (
    ('quiz', 'view_instructorprofile'),
    ('quiz', 'change_instructorprofile'),
    ('quiz', 'view_auditlog'),
    ('quiz', 'view_securitylog'),
    ('auth', 'view_user'),
)

# Deterministic signed 64-bit advisory lock key for PostgreSQL bootstrap serialization
_POSTGRES_BOOTSTRAP_LOCK_KEY = 5999274627359462481


class Command(BaseCommand):
    help = "Securely bootstraps the initial Administrator account using hidden password input."

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Username for the initial Administrator'
        )
        parser.add_argument(
            '--email',
            type=str,
            help='Email address for the initial Administrator'
        )

    def _get_required_input(self, option_value, prompt_label, field_name):
        if option_value is not None:
            value = option_value.strip()
        else:
            try:
                value = input(f"{prompt_label}: ").strip()
            except (EOFError, KeyboardInterrupt, OSError) as exc:
                raise CommandError(f"{field_name} input aborted or unsupported in this terminal.") from exc

        if not value:
            raise CommandError(f"{field_name} cannot be empty.")
        return value

    def _prompt_password_securely(self):
        """
        Prompts for and confirms the Administrator password without echoing.
        Refuses to proceed if terminal echo cannot be suppressed (prevents
        fallback_getpass from echoing plaintext passwords).
        """
        is_real_getpass = getattr(getpass.getpass, '__module__', '') == 'getpass'
        if is_real_getpass:
            if getpass.getpass is getpass.fallback_getpass:
                raise CommandError(
                    "Terminal echo control is unavailable. "
                    "Aborting password prompt to prevent accidental password exposure."
                )
            if not (sys.stdin and hasattr(sys.stdin, 'isatty') and sys.stdin.isatty()):
                raise CommandError(
                    "Secure hidden password input requires an interactive terminal (TTY). "
                    "Aborting to prevent unsupported input or password exposure."
                )

        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            try:
                pwd1 = getpass.getpass("Password: ")
                pwd2 = getpass.getpass("Password (again): ")
            except getpass.GetPassWarning as exc:
                raise CommandError(
                    "Cannot disable terminal echo for password entry. "
                    "Aborting to prevent accidental password exposure."
                ) from exc
            except (EOFError, KeyboardInterrupt, OSError) as exc:
                raise CommandError(
                    "Password input aborted or unsupported in this terminal."
                ) from exc

        if not pwd1:
            raise CommandError("Password cannot be empty.")
        if pwd1 != pwd2:
            raise CommandError("Passwords do not match.")
        return pwd1

    def _acquire_bootstrap_lock(self):
        """
        Acquires database-level concurrency protection inside transaction.atomic().

        Note: transaction.atomic() alone does not prevent concurrent bootstrap
        under READ COMMITTED isolation.
        - On PostgreSQL (production), pg_advisory_xact_lock serializes concurrent
          bootstrap invocations even before an Administrator group or user exists,
          and select_for_update() locks existing privileged rows.
        - Database limitation: SQLite does not support advisory locks or
          SELECT ... FOR UPDATE (has_select_for_update is False); concurrent
          SQLite writers rely on SQLite's database-level write lock.
        """
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    [_POSTGRES_BOOTSTRAP_LOCK_KEY]
                )

        if connection.features.has_select_for_update:
            list(Group.objects.select_for_update().filter(name='Administrator'))
            list(User.objects.select_for_update().filter(is_superuser=True, is_active=True))

    def _ensure_no_existing_privileged_accounts(self):
        """
        Refuses bootstrap if an Administrator group member or an active
        superuser account already exists. Never modifies existing accounts.
        """
        if User.objects.filter(groups__name='Administrator').exists():
            raise CommandError(
                "An Administrator account already exists. "
                "Creating a duplicate initial Administrator is not permitted."
            )

        if User.objects.filter(is_superuser=True, is_active=True).exists():
            raise CommandError(
                "An existing active superuser account was detected outside the Administrator group. "
                "Automatic bootstrap is refused; manual review is required before proceeding."
            )

    def _resolve_admin_permissions(self):
        """
        Resolves and validates every required permission in ADMIN_SCOPED_PERMISSIONS.
        Raises CommandError if any required permission is missing so no partial
        or unprivileged Administrator account is created.
        """
        resolved = []
        missing = []
        for app_label, codename in ADMIN_SCOPED_PERMISSIONS:
            perm = Permission.objects.filter(
                content_type__app_label=app_label,
                codename=codename
            ).first()
            if perm is None:
                missing.append(f"{app_label}.{codename}")
            else:
                resolved.append(perm)

        if missing:
            raise CommandError(
                "Required Administrator permissions are missing from the database: "
                + ", ".join(missing)
                + ". Ensure all migrations have been applied before running create_admin."
            )
        return resolved

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.MIGRATE_HEADING("--- Create Initial Administrator Account ---")
        )

        # Fail fast before prompting if a privileged account already exists
        self._ensure_no_existing_privileged_accounts()

        username = self._get_required_input(
            options.get('username'), "Username", "Username"
        )
        if User.objects.filter(username__iexact=username).exists():
            raise CommandError(
                f"A user with the username '{username}' already exists."
            )

        email = self._get_required_input(
            options.get('email'), "Email address", "Email address"
        )
        try:
            validate_email(email)
        except ValidationError as exc:
            raise CommandError(
                f"Invalid email address: {', '.join(exc.messages)}"
            ) from exc

        if User.objects.filter(email__iexact=email).exists():
            raise CommandError(
                f"A user with the email '{email}' already exists."
            )

        # Prompt securely with echo protection
        password = self._prompt_password_securely()

        # Validate password against Django's configured AUTH_PASSWORD_VALIDATORS
        candidate_user = User(username=username, email=email)
        try:
            validate_password(password, user=candidate_user)
        except ValidationError as exc:
            raise CommandError(
                "Password validation failed:\n- " + "\n- ".join(exc.messages)
            ) from exc

        # Atomically lock, validate permissions, create Administrator, and audit-log
        with transaction.atomic():
            self._acquire_bootstrap_lock()
            self._ensure_no_existing_privileged_accounts()

            if User.objects.filter(username__iexact=username).exists():
                raise CommandError(
                    f"A user with the username '{username}' already exists."
                )
            if User.objects.filter(email__iexact=email).exists():
                raise CommandError(
                    f"A user with the email '{email}' already exists."
                )

            required_permissions = self._resolve_admin_permissions()

            admin_group, _ = Group.objects.get_or_create(name='Administrator')
            admin_group.permissions.add(*required_permissions)

            # Least-privilege admin: staff access for Django Admin + Administrator group RBAC;
            # is_superuser remains False because all app & admin privileges are scoped via group.
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_staff=True,
                is_superuser=False,
                is_active=True,
            )
            user.groups.add(admin_group)

            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='ADMIN_CREATED',
                status='SUCCESS',
                details=(
                    f"Initial Administrator account '{user.username}' ({user.email}) "
                    "created via create_admin management command."
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"\nSuccessfully created initial Administrator '{user.username}' ({user.email}) "
                f"with role 'Administrator'."
            )
        )
