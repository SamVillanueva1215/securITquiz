import datetime
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


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

    # Master additions for examination control & results release
    passing_percentage = models.FloatField(
        default=50.0,
        help_text="Passing grade percentage (0.0 to 100.0)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive quizzes cannot be seen or attempted by students"
    )
    results_released = models.BooleanField(
        default=False,
        help_text="When true, students can view their scores, submitted answers, and correct answers"
    )

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

    # Version 1: Legacy signatures (student, quiz, score, percentage, timestamp)
    # Version 2: Enhanced signatures including canonical submitted answers JSON
    signature_version = models.PositiveSmallIntegerField(default=1)

    submitted_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_passed(self):
        pass_pct = self.quiz.passing_percentage if self.quiz else 50.0
        return self.percentage >= pass_pct

    def __str__(self):
        return f"{self.student.username} - {self.quiz.title}"


class ActiveSession(models.Model):
    """
    Enforces Single Active Session Protection across Students and Instructors.
    Tracks the single valid session key and inactivity timestamp.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='active_session'
    )
    session_key = models.CharField(max_length=40, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self, timeout_minutes=5):
        return timezone.now() - self.last_activity > datetime.timedelta(minutes=timeout_minutes)

    def __str__(self):
        return f"ActiveSession: {self.user.username} ({self.session_key})"


class QuizAttempt(models.Model):
    """
    Manages in-progress examination sessions to preserve state across page refreshes,
    enforce sequential question locking, preserve the examination countdown timer,
    and guarantee stable question randomization throughout the attempt.
    """
    student = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='quiz_attempts'
    )
    quiz = models.ForeignKey(
        Quiz,
        on_delete=models.CASCADE,
        related_name='attempts'
    )
    started_at = models.DateTimeField(default=timezone.now)
    deadline = models.DateTimeField()
    question_order = models.JSONField(
        default=list,
        blank=True,
        help_text="Stable randomized order of question IDs for this attempt"
    )
    saved_answers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Saved student answers mapped by str(question_id)"
    )
    locked_question_ids = models.JSONField(
        default=list,
        blank=True,
        help_text="Question IDs that have been locked and can no longer be modified"
    )
    current_question_index = models.PositiveIntegerField(default=0)
    is_completed = models.BooleanField(default=False)

    class Meta:
        unique_together = ('student', 'quiz')

    def __str__(self):
        return f"Attempt: {self.student.username} on {self.quiz.title} (Completed: {self.is_completed})"


class SecurityLog(models.Model):
    username_attempted = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_success = models.BooleanField(default=False)
    action = models.CharField(
        max_length=50,
        default='LOGIN',
        help_text="Specific security event action (e.g. LOGIN_SUCCESS, BLOCKED_CONCURRENT_LOGIN, LOGOUT)"
    )

    def __str__(self):
        return f"{self.username_attempted} - {self.action} ({self.timestamp})"


class AuditLog(models.Model):
    """
    Centralized security and operational audit trail.
    Tracks authentication, quiz management, examination lifecycle, and cryptographic verification.
    """
    ACTION_CHOICES = (
        # Authentication
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('CONCURRENT_LOGIN_BLOCKED', 'Concurrent Login Blocked'),
        ('DEVICE_SWITCH_CONFIRMED', 'Device Switch Confirmed'),
        ('DEVICE_SWITCH_CANCELLED', 'Device Switch Cancelled'),
        ('SESSION_EXPIRED', 'Session Inactivity Expired'),
        # Quiz Management
        ('QUIZ_CREATED', 'Quiz Created'),
        ('QUIZ_EDITED', 'Quiz Edited'),
        ('QUIZ_STATUS_TOGGLED', 'Quiz Status Toggled'),
        ('RESULTS_RELEASED', 'Results Released'),
        ('RESULTS_HIDDEN', 'Results Hidden'),
        ('RESULTS_EXPORTED', 'Results Exported'),
        # Examination
        ('PIN_VERIFY_SUCCESS', 'PIN Verification Success'),
        ('PIN_VERIFY_FAILED', 'PIN Verification Failed'),
        ('EXAM_ATTEMPT_STARTED', 'Exam Attempt Started'),
        ('EXAM_ATTEMPT_RESUMED', 'Exam Attempt Resumed'),
        ('ANSWER_SAVED_LOCKED', 'Answer Saved and Locked'),
        ('EXAM_SUBMITTED', 'Exam Submitted'),
        ('EXAM_TIMEOUT_SUBMITTED', 'Exam Auto-Submitted on Timeout'),
        ('UNAUTHORIZED_ACCESS_ATTEMPT', 'Unauthorized Access Attempt'),
        # Cryptography
        ('DSA_SIGNATURE_GENERATED', 'DSA Signature Generated'),
        ('DSA_VERIFY_SUCCESS', 'DSA Verification Success'),
        ('DSA_VERIFY_FAILED', 'DSA Verification Failed (Tamper Alert)'),
    )

    actor = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_records'
    )
    actor_username = models.CharField(max_length=150)
    action = models.CharField(max_length=64, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    quiz = models.ForeignKey(
        Quiz,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_records'
    )
    submission = models.ForeignKey(
        QuizSubmission,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_records'
    )
    status = models.CharField(max_length=20, default='SUCCESS')
    details = models.TextField(blank=True)

    def __str__(self):
        return f"[{self.timestamp}] {self.actor_username} - {self.action} ({self.status})"
