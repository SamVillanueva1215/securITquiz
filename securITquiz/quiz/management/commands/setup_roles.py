
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group


class Command(BaseCommand):
    help = "Creates the default Student and Instructor groups."

    def handle(self, *args, **options):
        roles = ["Student", "Instructor"]

        for role in roles:
            group, created = Group.objects.get_or_create(name=role)

            if created:
                self.stdout.write(
                    self.style.SUCCESS(f"{role} group created successfully.")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f"{role} group already exists.")
                )

        self.stdout.write(
            self.style.SUCCESS("Account roles setup completed!")
        )
