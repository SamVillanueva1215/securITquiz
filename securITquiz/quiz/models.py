from django.db import models
from django.contrib.auth.models import User


class StudentProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='student_profile'
    )
    full_name = models.CharField(max_length=200)
    student_id = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return f"{self.full_name} ({self.student_id})"


class Quiz(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    time_limit_minutes = models.IntegerField(default=15)
    deadline = models.DateTimeField()
    access_pin = models.CharField(max_length=6)
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_quizzes'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class Question(models.Model):
    QUESTION_TYPES = (
        ('MCQ', 'Multiple Choice'),
        ('TF', 'True/False'),
        ('ID', 'Identification'),
    )

    quiz = models.ForeignKey(
        Quiz,
        on_delete=models.CASCADE,
        related_name='questions'
    )
    question_text = models.TextField()
    question_type = models.CharField(
        max_length=3,
        choices=QUESTION_TYPES,
        default='MCQ'
    )
    option_a = models.CharField(max_length=200, blank=True, null=True)
    option_b = models.CharField(max_length=200, blank=True, null=True)
    option_c = models.CharField(max_length=200, blank=True, null=True)
    option_d = models.CharField(max_length=200, blank=True, null=True)
    correct_answer = models.CharField(max_length=200)

    def __str__(self):
        return f"{self.quiz.title} - {self.question_text[:30]}"


class QuizSubmission(models.Model):
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='submissions'
    )
    quiz = models.ForeignKey(
        Quiz,
        on_delete=models.CASCADE,
        related_name='submissions'
    )
    score = models.FloatField()
    percentage = models.FloatField()
    dsa_signature = models.TextField()
    answers = models.JSONField(default=dict, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.student.username} - {self.quiz.title}"


class SecurityLog(models.Model):
    username_attempted = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_success = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username_attempted} - {self.timestamp}"
