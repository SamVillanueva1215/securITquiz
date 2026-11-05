
from django import forms
from django.contrib.auth.models import User, Group
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.db import transaction

from .models import StudentProfile


class EmailOrUsernameAuthenticationForm(AuthenticationForm):
    """
    Login form allowing students and instructors to log in using
    either their username or university email address.
    """
    username = forms.CharField(
        label="Username or Email",
        widget=forms.TextInput(
            attrs={
                "placeholder": "Enter username or email",
                "autofocus": True,
                "style": "width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"
            }
        )
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Enter password",
                "style": "width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;"
            }
        )
    )


class StudentRegistrationForm(UserCreationForm):

    full_name = forms.CharField(
        max_length=200,
        label="Full Name"
    )

    student_id = forms.CharField(
        max_length=50,
        label="Student ID"
    )

    email = forms.EmailField(
        label="University Email"
    )

    class Meta:
        model = User
        fields = (
            "full_name",
            "student_id",
            "email",
            "username",
        )

    def clean_email(self):
        email = self.cleaned_data.get("email")

        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "This email address is already registered."
            )

        return email

    def clean_student_id(self):
        student_id = self.cleaned_data.get("student_id")

        if StudentProfile.objects.filter(student_id=student_id).exists():
            raise forms.ValidationError(
                "This Student ID is already registered."
            )

        return student_id

    @transaction.atomic
    def save(self, commit=True):
        user = super().save(commit=False)

        user.email = self.cleaned_data["email"]
        user.is_staff = False
        user.is_superuser = False

        if commit:
            user.save()

            StudentProfile.objects.create(
                user=user,
                full_name=self.cleaned_data["full_name"],
                student_id=self.cleaned_data["student_id"]
            )

            student_group, created = Group.objects.get_or_create(
                name="Student"
            )

            user.groups.add(student_group)

        return user
