import getpass
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User, Group


class Command(BaseCommand):
    help = "Creates an instructor account and automatically assigns the Instructor role."

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            help='Username for the instructor'
        )
        parser.add_argument(
            '--email',
            type=str,
            help='Email address for the instructor'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Password for the instructor'
        )
        parser.add_argument(
            '--first-name',
            type=str,
            default='',
            help='First name of the instructor'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            default='',
            help='Last name of the instructor'
        )

    def handle(self, *args, **options):
        username = options.get('username')
        email = options.get('email')
        password = options.get('password')
        first_name = options.get('first_name', '')
        last_name = options.get('last_name', '')

        self.stdout.write(self.style.MIGRATE_HEADING("--- Create Instructor Account ---"))

        # Prompt for username if not provided
        while not username:
            entered = input("Username: ").strip()
            if entered:
                username = entered
            else:
                self.stderr.write("Username cannot be empty.")

        # Check if username exists
        if User.objects.filter(username__iexact=username).exists():
            raise CommandError(f"A user with the username '{username}' already exists.")

        # Prompt for email if not provided
        while not email:
            entered = input("Email address: ").strip()
            if entered:
                email = entered
            else:
                self.stderr.write("Email cannot be empty.")

        # Check if email exists
        if User.objects.filter(email__iexact=email).exists():
            raise CommandError(f"A user with the email '{email}' already exists.")

        # Prompt for password if not provided
        while not password:
            pwd1 = getpass.getpass("Password: ")
            pwd2 = getpass.getpass("Password (again): ")
            if not pwd1:
                self.stderr.write("Password cannot be empty.")
            elif pwd1 != pwd2:
                self.stderr.write("Passwords do not match. Try again.")
            else:
                password = pwd1

        # Ensure the Instructor group exists
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        # Create user with secure password hashing (Argon2 configured in settings)
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_staff=False,
            is_superuser=False
        )

        # Assign Instructor group
        user.groups.add(instructor_group)

        self.stdout.write(
            self.style.SUCCESS(
                f"\nSuccessfully created Instructor '{user.username}' ({user.email}) "
                f"with role 'Instructor'."
            )
        )
