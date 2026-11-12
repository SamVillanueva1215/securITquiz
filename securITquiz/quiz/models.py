import datetime
from collections.abc import Mapping
from django.apps import apps
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


def get_session_inactivity_timeout_seconds(default=1800):
    """
    Safely coerces settings.SESSION_INACTIVITY_TIMEOUT to a positive integer
    number of seconds, falling back to `default` (1800s / 30 min) on invalid values.
    """
    raw_value = getattr(settings, 'SESSION_INACTIVITY_TIMEOUT', default)
    if isinstance(raw_value, bool):
        return default
    try:
        seconds = int(raw_value)
    except (TypeError, ValueError):
        return default
    return seconds if seconds > 0 else default


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


class InstructorProfile(models.Model):
    """
    Manages instructor registration, academic affiliation, and administrator approval lifecycle.
    Enforces that access to instructor features is strictly gated by the single status field.
    """
    STATUS_CHOICES = (
        ('PENDING', 'Pending Approval'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    )

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='instructor_profile'
    )
    full_name = models.CharField(max_length=200)
    department = models.CharField(max_length=200, blank=True)
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default='PENDING',
        db_index=True
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='reviewed_instructors'
    )
    rejection_reason = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(status__in=['PENDING', 'APPROVED', 'REJECTED']),
                name='valid_instructor_status'
            )
        ]

    def is_authorized(self):
        return self.status == 'APPROVED'

    def approve(self, reviewer):
        """
        Approves the instructor application.
        Only users in the Administrator group or superusers may approve.
        Records reviewer, review timestamp, and clears any previous rejection reason.
        """
        if not reviewer or not (reviewer.is_superuser or reviewer.groups.filter(name='Administrator').exists()):
            raise PermissionError("Only administrators are authorized to approve instructor profiles.")
        self.status = 'APPROVED'
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.rejection_reason = ''
        self.save(update_fields=['status', 'reviewed_by', 'reviewed_at', 'rejection_reason'])
        AuditLog = apps.get_model('quiz', 'AuditLog')
        AuditLog.objects.create(
            actor=reviewer,
            actor_username=reviewer.username,
            action='INSTRUCTOR_APPROVED',
            status='APPROVED',
            details=f"Instructor '{self.user.username}' was approved by administrator '{reviewer.username}'."
        )

    def reject(self, reviewer, reason=''):
        """
        Rejects the instructor application.
        Only users in the Administrator group or superusers may reject.
        Records reviewer, review timestamp, and rejection reason.
        """
        if not reviewer or not (reviewer.is_superuser or reviewer.groups.filter(name='Administrator').exists()):
            raise PermissionError("Only administrators are authorized to reject instructor profiles.")
        self.status = 'REJECTED'
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.rejection_reason = reason or ''
        self.save(update_fields=['status', 'reviewed_by', 'reviewed_at', 'rejection_reason'])
        AuditLog = apps.get_model('quiz', 'AuditLog')
        AuditLog.objects.create(
            actor=reviewer,
            actor_username=reviewer.username,
            action='INSTRUCTOR_REJECTED',
            status='REJECTED',
            details=f"Instructor '{self.user.username}' was rejected by administrator '{reviewer.username}'. Reason: {self.rejection_reason}"
        )

    def __str__(self):
        return f"{self.full_name} ({self.user.username}) [{self.status}]"


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
    device_id = models.CharField(max_length=64, blank=True, default='', db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self, timeout_minutes=None, timeout_seconds=None):
        if timeout_seconds is None:
            if timeout_minutes is not None:
                try:
                    timeout_seconds = max(0, int(timeout_minutes) * 60)
                except (TypeError, ValueError):
                    timeout_seconds = get_session_inactivity_timeout_seconds()
            else:
                timeout_seconds = get_session_inactivity_timeout_seconds()
        else:
            try:
                timeout_seconds = max(0, int(timeout_seconds))
            except (TypeError, ValueError):
                timeout_seconds = get_session_inactivity_timeout_seconds()
        return timezone.now() - self.last_activity > datetime.timedelta(seconds=timeout_seconds)

    def __str__(self):
        return f"ActiveSession: {self.user.username} ({self.session_key})"


class DeviceAuthorizationRequest(models.Model):
    """
    Manages mutual two-device authentication authorization requests.
    When a user attempts to log in from Device B while Device A has an active session:
    - Device B creates a pending request with a 1-minute expiration window.
    - Device A (the currently active session) receives an on-screen authorization prompt.
    - If Device A approves within 1 minute, Device B is authenticated, and Device A is terminated.
    - If denied or expired, Device A remains active and Device B remains unauthenticated.
    """
    STATUS_CHOICES = (
        ('PENDING', 'Pending Approval'),
        ('APPROVED', 'Approved'),
        ('DENIED', 'Denied'),
        ('EXPIRED', 'Expired'),
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='device_auth_requests'
    )
    requesting_session_key = models.CharField(max_length=64, db_index=True)
    requesting_device_id = models.CharField(max_length=64, blank=True, default='', db_index=True)
    authorized_device_id = models.CharField(max_length=64, blank=True, default='')
    requesting_ip = models.GenericIPAddressField(null=True, blank=True)
    requesting_user_agent = models.CharField(max_length=255, blank=True, default='')
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default='PENDING',
        db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by_session_key = models.CharField(max_length=64, blank=True, null=True)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def check_expiration(self):
        if self.status == 'PENDING' and self.is_expired():
            self.status = 'EXPIRED'
            self.resolved_at = timezone.now()
            self.save(update_fields=['status', 'resolved_at'])
            return True
        return False

    def __str__(self):
        return f"AuthRequest #{self.id}: {self.user.username} from {self.requesting_ip} [{self.status}]"


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

    MAX_ID_ANSWER_LENGTH = 200

    class Meta:
        unique_together = ('student', 'quiz')

    def save_answers_from_post(self, post_data):
        """
        Validates and saves non-locked question answers from POST/mapping data
        into saved_answers without modifying locked questions or finalizing submission.
        """
        if self.is_completed:
            raise ValidationError("Cannot modify answers for a completed quiz attempt.")

        now = timezone.now()
        if self.quiz and self.quiz.deadline and now > self.quiz.deadline:
            raise ValidationError("Cannot modify answers after the quiz deadline has passed.")
        if self.deadline and now > self.deadline:
            raise ValidationError("Cannot modify answers after the attempt deadline has passed.")

        if not isinstance(post_data, Mapping):
            raise ValidationError("Submitted answers must be provided as a mapping.")

        locked = {str(qid) for qid in (self.locked_question_ids or [])}
        answers = dict(self.saved_answers or {})
        pending_updates = {}

        for q in self.quiz.questions.all():
            qid_str = str(q.id)
            field_name = f"question_{q.id}"
            if field_name not in post_data or qid_str in locked:
                continue

            raw_val = post_data.get(field_name)
            if not isinstance(raw_val, str):
                raise ValidationError(f"Malformed answer value for question {q.id}.")
            if '\x00' in raw_val:
                raise ValidationError(f"Invalid control character in answer for question {q.id}.")

            val = raw_val.strip()
            if q.question_type == 'MCQ':
                if val != '':
                    val = val.upper()
                    if val not in ('A', 'B', 'C', 'D'):
                        raise ValidationError(f"Invalid multiple-choice option for question {q.id}.")
            elif q.question_type == 'TF':
                if val != '':
                    val = val.capitalize()
                    if val not in ('True', 'False'):
                        raise ValidationError(f"Invalid True/False answer for question {q.id}.")
            elif q.question_type == 'ID':
                if len(val) > self.MAX_ID_ANSWER_LENGTH:
                    raise ValidationError(
                        f"Identification answer for question {q.id} exceeds {self.MAX_ID_ANSWER_LENGTH} characters."
                    )

            if answers.get(qid_str) != val:
                pending_updates[qid_str] = val

        if pending_updates:
            answers.update(pending_updates)
            self.saved_answers = answers
            self.save(update_fields=['saved_answers'])
            return True
        return False

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
        # Authentication & Session Lifecycle
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('SESSION_CREATED', 'Session Created'),
        ('SESSION_EXPIRED', 'Session Inactivity Expired'),
        ('SESSION_REVOKED', 'Session Revoked'),
        ('SESSION_LOGOUT', 'Session Logout'),
        ('CONCURRENT_LOGIN_BLOCKED', 'Concurrent Login Blocked'),
        ('DEVICE_SWITCH_CONFIRMED', 'Device Switch Confirmed'),
        ('DEVICE_SWITCH_CANCELLED', 'Device Switch Cancelled'),
        ('DEVICE_AUTH_REQUESTED', 'Device Authorization Requested'),
        ('DEVICE_AUTHORIZATION_REQUESTED', 'Device Authorization Requested'),
        ('DEVICE_AUTH_APPROVED', 'Device Authorization Approved'),
        ('DEVICE_AUTHORIZATION_APPROVED', 'Device Authorization Approved'),
        ('DEVICE_AUTH_DENIED', 'Device Authorization Denied'),
        ('DEVICE_AUTHORIZATION_DENIED', 'Device Authorization Denied'),
        ('DEVICE_AUTH_EXPIRED', 'Device Authorization Expired'),
        ('DEVICE_AUTHORIZATION_EXPIRED', 'Device Authorization Expired'),
        ('DEVICE_AUTHORIZATION_TRANSFERRED', 'Device Authorization Transferred'),
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
        # Instructor Account Lifecycle
        ('INSTRUCTOR_REGISTERED', 'Instructor Registered (Pending Approval)'),
        ('INSTRUCTOR_APPROVED', 'Instructor Approved'),
        ('INSTRUCTOR_REJECTED', 'Instructor Registration Rejected'),
        # Administrator Bootstrap & Governance
        ('ADMIN_CREATED', 'Administrator Account Created'),
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
    device_id = models.CharField(max_length=64, blank=True, default='')
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
