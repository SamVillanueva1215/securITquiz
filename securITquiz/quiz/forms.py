import secrets
import string
from django import forms
from django.utils import timezone
from django.contrib.auth.models import User, Group
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.db import transaction

from .models import StudentProfile, Quiz, Question


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


def generate_secure_pin(length=6):
    """
    Generates a cryptographically secure 6-character alphanumeric PIN
    using Python's secrets module and guarantees uniqueness against existing quizzes.
    """
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(100):
        pin = ''.join(secrets.choice(alphabet) for _ in range(length))
        if not Quiz.objects.filter(access_pin=pin).exists():
            return pin
    return pin


class QuizForm(forms.ModelForm):
    class Meta:
        model = Quiz
        fields = ['title', 'description', 'time_limit_minutes', 'deadline', 'access_pin']
        widgets = {
            'title': forms.TextInput(attrs={
                'placeholder': 'e.g. Midterm Cryptography Exam',
                'style': 'width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;'
            }),
            'description': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': 'Provide instructions, syllabus coverage, or rules for this quiz...',
                'style': 'width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;'
            }),
            'time_limit_minutes': forms.NumberInput(attrs={
                'min': 1,
                'placeholder': '15',
                'style': 'width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;'
            }),
            'deadline': forms.DateTimeInput(attrs={
                'type': 'datetime-local',
                'style': 'width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;'
            }),
            'access_pin': forms.TextInput(attrs={
                'maxlength': 6,
                'placeholder': '6-character PIN',
                'style': 'width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; text-transform: uppercase; font-family: monospace; font-size: 16px; letter-spacing: 2px;'
            }),
        }

    def clean_access_pin(self):
        access_pin = self.cleaned_data.get('access_pin', '').strip().upper()
        if len(access_pin) != 6 or not access_pin.isalnum():
            raise forms.ValidationError("Access PIN must be exactly 6 alphanumeric characters.")

        # Ensure uniqueness against existing quizzes
        query = Quiz.objects.filter(access_pin=access_pin)
        if self.instance and self.instance.pk:
            query = query.exclude(pk=self.instance.pk)
        if query.exists():
            raise forms.ValidationError(
                f"The access PIN '{access_pin}' is already in use by another quiz. "
                "Please choose or generate a unique PIN."
            )
        return access_pin

    def clean_deadline(self):
        deadline = self.cleaned_data.get('deadline')
        if deadline and deadline <= timezone.now():
            raise forms.ValidationError("The deadline must be set to a future date and time.")
        return deadline

    def clean_time_limit_minutes(self):
        time_limit = self.cleaned_data.get('time_limit_minutes')
        if time_limit is None or time_limit < 1:
            raise forms.ValidationError("Time limit must be at least 1 minute.")
        return time_limit


class PinVerificationForm(forms.Form):
    """
    Form for students to enter the 6-character Access PIN before starting a quiz.
    """
    access_pin = forms.CharField(
        max_length=6,
        label="Quiz Access PIN",
        widget=forms.TextInput(attrs={
            'maxlength': 6,
            'placeholder': '6-CHARACTER PIN',
            'autofocus': True,
            'style': 'width: 100%; padding: 12px; border: 2px solid #003366; border-radius: 6px; box-sizing: border-box; text-transform: uppercase; font-family: monospace; font-size: 20px; letter-spacing: 4px; text-align: center;'
        })
    )

    def clean_access_pin(self):
        pin = self.cleaned_data.get('access_pin', '').strip().upper()
        if len(pin) != 6 or not pin.isalnum():
            raise forms.ValidationError("Access PIN must be exactly 6 alphanumeric characters.")
        return pin


def validate_questions_data(raw_questions):
    """
    Validates a list of question dictionaries:
    1. At least one question is required.
    2. Multiple Choice (MCQ):
       - Requires question_text.
       - Requires all four options (A, B, C, D).
       - Requires exactly one valid correct answer in ('A', 'B', 'C', 'D').
    3. True/False (TF):
       - Requires question_text.
       - Requires correct_answer in ('True', 'False').
       - Sets option_a='True', option_b='False', option_c=None, option_d=None.
    4. Identification (ID):
       - Requires question_text.
       - Requires non-empty correct_answer.
       - Sets option_a=None, option_b=None, option_c=None, option_d=None.
    Returns: (validated_questions_list, error_messages_list)
    """
    errors = []
    validated = []

    if not raw_questions or len(raw_questions) == 0:
        errors.append("At least one question is required before saving a quiz.")
        return [], errors

    for idx, q in enumerate(raw_questions, start=1):
        q_text = str(q.get('question_text', '')).strip()
        q_type = str(q.get('question_type', '')).strip().upper()

        if not q_text:
            errors.append(f"Question #{idx}: Question text cannot be empty.")
            continue

        if q_type not in ['MCQ', 'TF', 'ID']:
            errors.append(f"Question #{idx}: Invalid question type '{q_type}'. Must be Multiple Choice (MCQ), True/False (TF), or Identification (ID).")
            continue

        if q_type == 'MCQ':
            opt_a = str(q.get('option_a', '')).strip()
            opt_b = str(q.get('option_b', '')).strip()
            opt_c = str(q.get('option_c', '')).strip()
            opt_d = str(q.get('option_d', '')).strip()
            correct = str(q.get('correct_answer', '')).strip().upper()

            missing = []
            if not opt_a: missing.append("Option A")
            if not opt_b: missing.append("Option B")
            if not opt_c: missing.append("Option C")
            if not opt_d: missing.append("Option D")

            if missing:
                errors.append(f"Question #{idx} (MCQ): {', '.join(missing)} is required.")

            if correct not in ['A', 'B', 'C', 'D']:
                errors.append(f"Question #{idx} (MCQ): Exactly one correct answer must be selected (Option A, B, C, or D).")

            validated.append({
                'id': q.get('id'),
                'question_text': q_text,
                'question_type': 'MCQ',
                'option_a': opt_a,
                'option_b': opt_b,
                'option_c': opt_c,
                'option_d': opt_d,
                'correct_answer': correct
            })

        elif q_type == 'TF':
            raw_correct = str(q.get('correct_answer', '')).strip().capitalize()
            if raw_correct not in ['True', 'False']:
                errors.append(f"Question #{idx} (True/False): The correct answer must be either 'True' or 'False'.")

            validated.append({
                'id': q.get('id'),
                'question_text': q_text,
                'question_type': 'TF',
                'option_a': 'True',
                'option_b': 'False',
                'option_c': None,
                'option_d': None,
                'correct_answer': raw_correct
            })

        elif q_type == 'ID':
            raw_correct = str(q.get('correct_answer', '')).strip()
            if not raw_correct:
                errors.append(f"Question #{idx} (Identification): The correct answer is required.")

            validated.append({
                'id': q.get('id'),
                'question_text': q_text,
                'question_type': 'ID',
                'option_a': None,
                'option_b': None,
                'option_c': None,
                'option_d': None,
                'correct_answer': raw_correct
            })

    if errors:
        return [], errors

    return validated, []
