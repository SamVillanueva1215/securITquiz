"""
securITquiz - Email Notification Engine
Handles event-based notifications using Django's email framework.
Safely handles email delivery failures so email errors never block submissions or logins.
"""

import logging
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)


def send_safe_email(subject, message, recipient_list):
    """
    Safely dispatches an email to the specified recipient list.
    Gracefully catches any network, SMTP, or configuration errors to ensure
    business logic (such as quiz submissions or authentications) is never interrupted.
    """
    if not recipient_list:
        return False

    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@securitquiz.edu')
    try:
        send_mail(
            subject=f"[securITquiz] {subject}",
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
            fail_silently=False
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to send email to {recipient_list}: {str(e)}")
        return False


def notify_student_submission_confirmation(submission):
    """
    Sends a confirmation email to the student upon completing a quiz attempt.
    """
    student = submission.student
    quiz = submission.quiz
    if not student.email:
        return False

    subject = f"Quiz Submission Confirmation - {quiz.title}"
    body = (
        f"Dear {student.first_name or student.username},\n\n"
        f"Your submission for the quiz '{quiz.title}' has been successfully recorded and "
        f"cryptographically signed using the Digital Signature Algorithm (DSA).\n\n"
        f"Submission Details:\n"
        f"- Quiz: {quiz.title}\n"
        f"- Submitted At: {submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"- Signature Version: {submission.signature_version}\n\n"
        f"Once your instructor releases the official results, you will be able to review your "
        f"detailed score, submitted answers, and question key on your student dashboard.\n\n"
        f"Best regards,\n"
        f"securITquiz Examination System"
    )
    return send_safe_email(subject, body, [student.email])


def notify_instructor_new_submission(submission):
    """
    Notifies the instructor who created the quiz whenever a student submits an attempt.
    """
    quiz = submission.quiz
    instructor = quiz.created_by
    if not instructor or not instructor.email:
        return False

    subject = f"New Submission Received - {quiz.title}"
    body = (
        f"Dear {instructor.first_name or instructor.username},\n\n"
        f"A student has submitted an attempt for your quiz '{quiz.title}'.\n\n"
        f"Student: {submission.student.username} ({getattr(getattr(submission.student, 'student_profile', None), 'student_id', 'N/A')})\n"
        f"Score: {submission.score:.1f} ({submission.percentage:.1f}%)\n"
        f"Status: {'PASSED' if submission.is_passed else 'FAILED'}\n"
        f"Submitted At: {submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"You can review detailed answers and cryptographic verification on your instructor dashboard.\n\n"
        f"securITquiz Notification Service"
    )
    return send_safe_email(subject, body, [instructor.email])


def notify_instructor_dsa_failure(submission):
    """
    Sends an urgent security alert to the quiz instructor when DSA signature verification fails.
    """
    quiz = submission.quiz
    instructor = quiz.created_by
    if not instructor or not instructor.email:
        return False

    subject = f"URGENT SECURITY ALERT: DSA Signature Verification Failed - {quiz.title}"
    body = (
        f"ATTENTION: {instructor.first_name or instructor.username},\n\n"
        f"A cryptographic integrity failure was detected during verification of a quiz submission!\n\n"
        f"Submission Details:\n"
        f"- Submission ID: {submission.id}\n"
        f"- Quiz: {quiz.title} (ID: {quiz.id})\n"
        f"- Student: {submission.student.username}\n"
        f"- Stored Score: {submission.score}\n"
        f"- Signature Version: {submission.signature_version}\n"
        f"- Timestamp: {submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"Warning: The Digital Signature Algorithm (DSA) signature does NOT match the submission payload. "
        f"This indicates potential database tampering, answer modification, or record corruption. "
        f"Please inspect the security audit trail immediately.\n\n"
        f"securITquiz Security Monitoring"
    )
    return send_safe_email(subject, body, [instructor.email])


def notify_students_results_released(quiz):
    """
    Notifies all students who completed a quiz that the instructor has released official results.
    """
    submissions = quiz.submissions.select_related('student').all()
    emails = [sub.student.email for sub in submissions if sub.student.email]
    if not emails:
        return False

    subject = f"Results Released - {quiz.title}"
    body = (
        f"Official results and answer reviews for '{quiz.title}' have been released by your instructor.\n\n"
        f"Please log in to your securITquiz Student Dashboard to view your score, pass/fail status, "
        f"and individual question reviews.\n\n"
        f"securITquiz Examination System"
    )
    # Send individually or bcc to avoid exposing student emails
    for email in set(emails):
        send_safe_email(subject, body, [email])
    return True


def notify_suspicious_security_event(user, ip_address, event_type, details):
    """
    Alerts the user or administrator when a suspicious authentication or security event occurs.
    """
    if not user or not user.email:
        return False

    subject = f"Security Notice: {event_type}"
    body = (
        f"Hello {user.first_name or user.username},\n\n"
        f"A security event was recorded for your securITquiz account:\n"
        f"- Event: {event_type}\n"
        f"- IP Address: {ip_address}\n"
        f"- Details: {details}\n\n"
        f"If you did not perform this activity, please contact your instructor or system administrator immediately.\n\n"
        f"securITquiz Security Operations"
    )
    return send_safe_email(subject, body, [user.email])
