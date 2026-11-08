import csv
import json
import random
import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone

from .models import (
    Quiz,
    QuizSubmission,
    Question,
    StudentProfile,
    ActiveSession,
    QuizAttempt,
    SecurityLog,
    AuditLog
)
from .forms import (
    StudentRegistrationForm,
    EmailOrUsernameAuthenticationForm,
    QuizForm,
    PinVerificationForm,
    validate_questions_data,
    generate_secure_pin
)
from .decorators import student_required, instructor_required
from .crypto import generate_dsa_signature, verify_dsa_signature
from .middleware import get_client_ip
from .notifications import (
    notify_student_submission_confirmation,
    notify_instructor_new_submission,
    notify_instructor_dsa_failure,
    notify_students_results_released,
    notify_suspicious_security_event
)


# ==============================================================================
# Public Views & Authentication
# ==============================================================================

def home(request):
    return render(request, 'quiz/index.html')


def register(request):
    if request.user.is_authenticated:
        if request.user.groups.filter(name='Instructor').exists():
            return redirect('instructor_dashboard')
        return redirect('student_dashboard')

    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            ip = get_client_ip(request)
            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='LOGIN_SUCCESS',
                ip_address=ip,
                status='REGISTERED',
                details=f"Student account registered: {user.username}"
            )
            messages.success(
                request,
                'Your student account has been created successfully! You can now log in.'
            )
            return redirect('login')
    else:
        form = StudentRegistrationForm()

    return render(request, 'quiz/register.html', {
        'form': form
    })


def user_login(request):
    """
    Handles user authentication with Single Active Session Protection.
    If an existing active session is detected on another device/browser:
    - Prompts user with device conflict warning.
    - Prevents silent replacement.
    - Allows user to confirm device switch or cancel.
    """
    if request.user.is_authenticated:
        if request.user.groups.filter(name='Instructor').exists():
            return redirect('instructor_dashboard')
        return redirect('student_dashboard')

    if request.method == 'POST':
        form = EmailOrUsernameAuthenticationForm(request, data=request.POST)
        ip = get_client_ip(request)

        if form.is_valid():
            user = form.get_user()
            is_student = user.groups.filter(name='Student').exists()
            is_instructor = user.groups.filter(name='Instructor').exists()

            if not (is_student or is_instructor):
                messages.error(request, 'Your account does not have a valid securITquiz role.')
                return render(request, 'quiz/login.html', {'form': form})

            # Check for existing active session (Single Active Session Protection)
            active_session = ActiveSession.objects.filter(user=user).first()
            current_session_key = request.session.session_key

            # If user has an active, unexpired session on another device/session
            if active_session and not active_session.is_expired(timeout_minutes=5):
                if active_session.session_key != current_session_key:
                    # Log blocked concurrent attempt
                    SecurityLog.objects.create(
                        username_attempted=user.username,
                        ip_address=ip,
                        is_success=False,
                        action='BLOCKED_CONCURRENT_LOGIN'
                    )
                    AuditLog.objects.create(
                        actor=user,
                        actor_username=user.username,
                        action='CONCURRENT_LOGIN_BLOCKED',
                        ip_address=ip,
                        status='BLOCKED',
                        details=f"Second device login attempt detected from IP {ip}."
                    )

                    # Store pending login in session for explicit user confirmation
                    request.session['pending_switch_user_id'] = user.id
                    request.session['pending_switch_backend'] = user.backend

                    return render(request, 'quiz/device_conflict.html', {
                        'account_username': user.username,
                        'existing_ip': active_session.ip_address or 'Unknown',
                        'last_active': active_session.last_activity,
                    })

            # No conflict: log in user and establish ActiveSession
            with transaction.atomic():
                login(request, user)
                new_session_key = request.session.session_key
                if not new_session_key:
                    request.session.save()
                    new_session_key = request.session.session_key

                ActiveSession.objects.update_or_create(
                    user=user,
                    defaults={
                        'session_key': new_session_key,
                        'ip_address': ip,
                        'last_activity': timezone.now()
                    }
                )

                SecurityLog.objects.create(
                    username_attempted=user.username,
                    ip_address=ip,
                    is_success=True,
                    action='LOGIN_SUCCESS'
                )
                AuditLog.objects.create(
                    actor=user,
                    actor_username=user.username,
                    action='LOGIN_SUCCESS',
                    ip_address=ip,
                    status='SUCCESS',
                    details="User logged in successfully."
                )

            if is_instructor:
                return redirect('instructor_dashboard')
            return redirect('student_dashboard')

        else:
            username_attempted = request.POST.get('username', 'Unknown')
            SecurityLog.objects.create(
                username_attempted=username_attempted,
                ip_address=ip,
                is_success=False,
                action='LOGIN_FAILED'
            )
            AuditLog.objects.create(
                actor_username=username_attempted,
                action='LOGIN_FAILED',
                ip_address=ip,
                status='FAILED',
                details="Invalid username/email or password credentials."
            )
            messages.error(request, 'Invalid username/email or password.')

    else:
        form = EmailOrUsernameAuthenticationForm()

    return render(request, 'quiz/login.html', {
        'form': form
    })


def confirm_device_switch(request):
    """
    Handles confirmed device switch: invalidates old session, establishes new session.
    """
    if request.method != 'POST':
        return redirect('login')

    user_id = request.session.get('pending_switch_user_id')
    backend = request.session.get('pending_switch_backend')

    if not user_id:
        messages.error(request, "No pending login session found. Please log in again.")
        return redirect('login')

    user = get_object_or_404(User, id=user_id)
    ip = get_client_ip(request)

    with transaction.atomic():
        # Invalidate old session in Django session database
        old_active = ActiveSession.objects.filter(user=user).first()
        if old_active:
            Session.objects.filter(session_key=old_active.session_key).delete()

        # Authorize new session
        user.backend = backend
        login(request, user)
        new_key = request.session.session_key
        if not new_key:
            request.session.save()
            new_key = request.session.session_key

        ActiveSession.objects.update_or_create(
            user=user,
            defaults={
                'session_key': new_key,
                'ip_address': ip,
                'last_activity': timezone.now()
            }
        )

        SecurityLog.objects.create(
            username_attempted=user.username,
            ip_address=ip,
            is_success=True,
            action='DEVICE_SWITCH_CONFIRMED'
        )
        AuditLog.objects.create(
            actor=user,
            actor_username=user.username,
            action='DEVICE_SWITCH_CONFIRMED',
            ip_address=ip,
            status='CONFIRMED',
            details=f"Device switch confirmed from IP {ip}. Previous session was invalidated."
        )

    # Clean up pending state
    request.session.pop('pending_switch_user_id', None)
    request.session.pop('pending_switch_backend', None)

    messages.success(request, "Device switch confirmed. Your previous session has been terminated.")
    if user.groups.filter(name='Instructor').exists():
        return redirect('instructor_dashboard')
    return redirect('student_dashboard')


def cancel_device_switch(request):
    """
    Cancels device switch request and preserves the existing session on the other device.
    """
    user_id = request.session.get('pending_switch_user_id')
    ip = get_client_ip(request)
    if user_id:
        user = User.objects.filter(id=user_id).first()
        uname = user.username if user else 'Unknown'
        SecurityLog.objects.create(
            username_attempted=uname,
            ip_address=ip,
            is_success=False,
            action='DEVICE_SWITCH_CANCELLED'
        )
        AuditLog.objects.create(
            actor=user,
            actor_username=uname,
            action='DEVICE_SWITCH_CANCELLED',
            ip_address=ip,
            status='CANCELLED',
            details="Device switch was cancelled by user. Original session preserved."
        )

    request.session.pop('pending_switch_user_id', None)
    request.session.pop('pending_switch_backend', None)
    messages.info(request, "Login cancelled. Your existing session remains active on your other device.")
    return redirect('login')


def user_logout(request):
    if request.user.is_authenticated:
        ip = get_client_ip(request)
        ActiveSession.objects.filter(user=request.user).delete()
        SecurityLog.objects.create(
            username_attempted=request.user.username,
            ip_address=ip,
            is_success=True,
            action='LOGOUT'
        )
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='LOGOUT',
            ip_address=ip,
            status='SUCCESS',
            details="User logged out cleanly."
        )

    logout(request)
    messages.success(request, 'You have successfully logged out.')
    return redirect('login')


# ==============================================================================
# Student Dashboard & Examination Workflow
# ==============================================================================

@student_required
def student_dashboard(request):
    """
    Renders available active quizzes and completed student submissions.
    """
    available_quizzes = Quiz.objects.filter(is_active=True).order_by('-created_at')

    completed_submissions = QuizSubmission.objects.filter(
        student=request.user
    ).select_related('quiz')

    completed_quiz_ids = set(completed_submissions.values_list('quiz_id', flat=True))

    return render(request, 'quiz/student_dashboard.html', {
        'available_quizzes': available_quizzes,
        'completed_quizzes': completed_submissions,
        'completed_quiz_ids': completed_quiz_ids,
        'now': timezone.now()
    })


@student_required
def verify_quiz_pin(request, quiz_id):
    """
    Renders the Access PIN verification page.
    Required before starting or resuming an exam attempt.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)
    ip = get_client_ip(request)

    # 1. Verify quiz is active
    if not quiz.is_active:
        messages.error(request, f"The quiz '{quiz.title}' is currently inactive and not accepting attempts.")
        return redirect('student_dashboard')

    # 2. Verify deadline
    if quiz.deadline and timezone.now() > quiz.deadline:
        messages.error(request, f"The deadline for '{quiz.title}' has passed. Submissions are no longer accepted.")
        return redirect('student_dashboard')

    # 3. Prevent duplicate submissions
    existing_submission = QuizSubmission.objects.filter(
        student=request.user,
        quiz=quiz
    ).first()
    if existing_submission:
        messages.warning(request, f"You have already submitted '{quiz.title}'. You cannot retake this quiz.")
        return redirect('quiz_result', submission_id=existing_submission.id)

    # 4. Verify questions exist
    if not quiz.questions.exists():
        messages.error(request, f"The quiz '{quiz.title}' has no questions available.")
        return redirect('student_dashboard')

    # 5. Check if attempt is in-progress
    existing_attempt = QuizAttempt.objects.filter(
        student=request.user,
        quiz=quiz,
        is_completed=False
    ).first()

    session_pin_key = f'pin_verified_quiz_{quiz.id}'

    # 6. Handle PIN verification
    if request.method == 'POST':
        form = PinVerificationForm(request.POST)
        if form.is_valid():
            entered_pin = form.cleaned_data['access_pin'].strip().upper()
            if entered_pin == quiz.access_pin.strip().upper():
                request.session[session_pin_key] = True
                request.session[f'verified_quiz_{quiz.id}_user_{request.user.id}'] = True
                request.session.pop(f'quiz_{quiz.id}_rendered', None)

                if existing_attempt:
                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='EXAM_ATTEMPT_RESUMED',
                        ip_address=ip,
                        quiz=quiz,
                        status='RESUMED',
                        details=f"In-progress attempt resumed after PIN re-verification (Question index {existing_attempt.current_question_index + 1})."
                    )
                    messages.success(request, f"Access PIN verified! Resuming '{quiz.title}'.")
                else:
                    # Initialize stable randomized question order
                    qids = list(quiz.questions.values_list('id', flat=True))
                    random.shuffle(qids)

                    calc_deadline = min(
                        timezone.now() + datetime.timedelta(minutes=quiz.time_limit_minutes),
                        quiz.deadline
                    )

                    new_attempt = QuizAttempt.objects.create(
                        student=request.user,
                        quiz=quiz,
                        deadline=calc_deadline,
                        question_order=qids,
                        saved_answers={},
                        locked_question_ids=[],
                        current_question_index=0
                    )
                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='EXAM_ATTEMPT_STARTED',
                        ip_address=ip,
                        quiz=quiz,
                        status='STARTED',
                        details=f"Exam attempt started for '{quiz.title}'. Deadline: {calc_deadline}."
                    )
                    messages.success(request, f"Access PIN verified! You may now begin '{quiz.title}'.")

                return redirect('take_quiz', quiz_id=quiz.id)
            else:
                AuditLog.objects.create(
                    actor=request.user,
                    actor_username=request.user.username,
                    action='PIN_VERIFY_FAILED',
                    ip_address=ip,
                    quiz=quiz,
                    status='FAILED',
                    details="Incorrect PIN entered."
                )
                messages.error(request, "Invalid Access PIN. Please check the PIN provided by your instructor and try again.")
    else:
        form = PinVerificationForm()

    return render(request, 'quiz/verify_pin.html', {
        'quiz': quiz,
        'form': form,
        'has_in_progress_attempt': bool(existing_attempt),
    })


@student_required
def take_quiz(request, quiz_id):
    """
    Renders the sequential examination interface.
    Features:
    - Checks deadline first.
    - Prevents duplicate submissions.
    - Requires Access PIN verification.
    - PIN re-entry required on page reload/refresh.
    - Preserves examination timer and in-progress answers across attempts.
    - Sequential question navigation: locks answered questions when moving forward.
    - Automatic submission on timer expiration.
    - Stable question randomization across attempt.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)
    ip = get_client_ip(request)

    # 1. Verify deadline
    if quiz.deadline and timezone.now() > quiz.deadline:
        messages.error(
            request,
            f"The deadline for '{quiz.title}' has passed. Submissions are no longer accepted."
        )
        return redirect('student_dashboard')

    # 2. Prevent duplicate submissions
    existing_submission = QuizSubmission.objects.filter(
        student=request.user,
        quiz=quiz
    ).first()
    if existing_submission:
        messages.warning(request, f"You have already submitted '{quiz.title}'.")
        return redirect('quiz_result', submission_id=existing_submission.id)

    # 3. Check PIN session authorization (supporting both session keys)
    session_pin_key = f'pin_verified_quiz_{quiz.id}'
    legacy_pin_key = f'verified_quiz_{quiz.id}_user_{request.user.id}'
    rendered_key = f'quiz_{quiz.id}_rendered'

    if not request.session.get(session_pin_key) and not request.session.get(legacy_pin_key):
        messages.warning(
            request,
            f"Please enter the Quiz Access PIN to begin '{quiz.title}'."
        )
        return redirect('verify_quiz_pin', quiz_id=quiz.id)

    # 3.1 Refresh Detection: if page was already rendered, require PIN re-verification (Part 4.2)
    if request.method == 'GET':
        if request.session.get(rendered_key):
            request.session.pop(session_pin_key, None)
            request.session.pop(legacy_pin_key, None)
            request.session.pop(rendered_key, None)
            messages.info(request, "Quiz page was refreshed. Please re-enter your Access PIN to continue your attempt.")
            return redirect('verify_quiz_pin', quiz_id=quiz.id)
        request.session[rendered_key] = True

    # 4. Fetch or create active attempt
    attempt = QuizAttempt.objects.filter(
        student=request.user,
        quiz=quiz,
        is_completed=False
    ).first()

    if not attempt:
        qids = list(quiz.questions.values_list('id', flat=True))
        random.shuffle(qids)
        calc_deadline = min(
            timezone.now() + datetime.timedelta(minutes=quiz.time_limit_minutes),
            quiz.deadline or (timezone.now() + datetime.timedelta(days=1))
        )
        attempt = QuizAttempt.objects.create(
            student=request.user,
            quiz=quiz,
            deadline=calc_deadline,
            question_order=qids,
            saved_answers={},
            locked_question_ids=[],
            current_question_index=0
        )

    # 5. Timer expiration enforcement (Server-side)
    now = timezone.now()
    remaining_seconds = int((attempt.deadline - now).total_seconds())

    if remaining_seconds <= 0:
        return _finalize_quiz_submission(request, quiz, attempt, is_timeout=True)

    # 6. Handle POST: saving answers & submitting
    if request.method == 'POST':
        for q in quiz.questions.all():
            field_name = f"question_{q.id}"
            if field_name in request.POST:
                student_ans = request.POST.get(field_name, "").strip()
                # Enforce that locked questions cannot be modified
                if str(q.id) not in attempt.locked_question_ids:
                    attempt.saved_answers[str(q.id)] = student_ans

        action = request.POST.get('action', 'submit_all')
        if action == 'submit_all' or action == 'submit':
            attempt.save()
            return _finalize_quiz_submission(request, quiz, attempt, is_timeout=False)

        attempt.save()
        return redirect('take_quiz', quiz_id=quiz.id)

    # 7. GET request: render the examination page

    questions_map = {q.id: q for q in quiz.questions.all()}
    ordered_qids = attempt.question_order or list(quiz.questions.values_list('id', flat=True))
    ordered_questions = [questions_map[qid] for qid in ordered_qids if qid in questions_map]
    if not ordered_questions:
        ordered_questions = list(quiz.questions.all())

    questions_with_status = []
    for q in ordered_questions:
        is_locked = str(q.id) in attempt.locked_question_ids
        saved_ans = attempt.saved_answers.get(str(q.id), '')
        questions_with_status.append({
            'question': q,
            'is_locked': is_locked,
            'saved_answer': saved_ans,
        })

    return render(request, 'quiz/take_quiz.html', {
        'quiz': quiz,
        'attempt': attempt,
        'questions_with_status': questions_with_status,
        'total_questions': len(questions_with_status),
        'remaining_seconds': max(0, remaining_seconds),
    })


def _finalize_quiz_submission(request, quiz, attempt, is_timeout=False):
    """
    Helper to grade saved answers, record submission with DSA v2 signature,
    update attempt status, send notifications, and record audit log.
    """
    ip = get_client_ip(request)
    questions = quiz.questions.all()
    total_questions = questions.count()
    correct_count = 0
    saved_answers = attempt.saved_answers

    for q in questions:
        ans = saved_answers.get(str(q.id), "").strip()
        is_corr = False
        if q.question_type == 'ID':
            is_corr = bool(ans and ans.lower() == q.correct_answer.strip().lower())
        elif q.question_type == 'TF':
            is_corr = bool(ans and ans.capitalize() == q.correct_answer.strip().capitalize())
        else:  # MCQ
            is_corr = bool(ans and ans.upper() == q.correct_answer.strip().upper())

        if is_corr:
            correct_count += 1

    score = float(correct_count)
    percentage = round((score / total_questions) * 100.0, 2) if total_questions > 0 else 0.0

    with transaction.atomic():
        submission = QuizSubmission(
            student=request.user,
            quiz=quiz,
            score=score,
            percentage=percentage,
            answers=saved_answers,
            signature_version=2,
            dsa_signature=""
        )
        submission.save()

        timestamp_str = submission.submitted_at.isoformat()
        submission.dsa_signature = generate_dsa_signature(
            student_username=request.user.username,
            quiz_id=quiz.id,
            score=score,
            percentage=percentage,
            timestamp_str=timestamp_str,
            answers=saved_answers,
            signature_version=2
        )
        submission.save(update_fields=['dsa_signature'])

        attempt.is_completed = True
        attempt.save()

        action_type = 'EXAM_TIMEOUT_SUBMITTED' if is_timeout else 'EXAM_SUBMITTED'
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action=action_type,
            ip_address=ip,
            quiz=quiz,
            submission=submission,
            status='SUBMITTED',
            details=f"Quiz completed ({'Automatic timeout' if is_timeout else 'Normal submit'}). Score: {score}/{total_questions} ({percentage}%)."
        )
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='DSA_SIGNATURE_GENERATED',
            ip_address=ip,
            quiz=quiz,
            submission=submission,
            status='SUCCESS',
            details=f"DSA v2 signature generated: {submission.dsa_signature[:16]}..."
        )

    # Invalidate session PIN flags
    session_pin_key = f'pin_verified_quiz_{quiz.id}'
    legacy_pin_key = f'verified_quiz_{quiz.id}_user_{request.user.id}'
    request.session.pop(session_pin_key, None)
    request.session.pop(legacy_pin_key, None)
    request.session.pop(f'quiz_{quiz.id}_rendered', None)

    # Dispatch email notifications
    notify_student_submission_confirmation(submission)
    notify_instructor_new_submission(submission)

    if is_timeout:
        messages.info(request, f"Time limit expired! Your answers for '{quiz.title}' were automatically submitted.")
    else:
        messages.success(request, f"Quiz '{quiz.title}' submitted successfully!")

    return redirect('quiz_result', submission_id=submission.id)


@student_required
def quiz_result(request, submission_id):
    """
    Displays the quiz results.
    Enforces results release gating: students only see scores and answer keys
    after the instructor explicitly releases results.
    """
    submission = get_object_or_404(
        QuizSubmission.objects.select_related('quiz', 'student'),
        id=submission_id
    )

    if submission.student != request.user:
        messages.error(request, "Access Denied: You cannot view another student's quiz results.")
        return redirect('student_dashboard')

    ip = get_client_ip(request)
    timestamp_str = submission.submitted_at.isoformat()
    is_dsa_valid = verify_dsa_signature(
        student_username=submission.student.username,
        quiz_id=submission.quiz.id,
        score=submission.score,
        percentage=submission.percentage,
        timestamp_str=timestamp_str,
        hex_signature=submission.dsa_signature,
        answers=submission.answers,
        signature_version=submission.signature_version
    )

    if is_dsa_valid:
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='DSA_VERIFY_SUCCESS',
            ip_address=ip,
            quiz=submission.quiz,
            submission=submission,
            status='VALID',
            details=f"DSA v{submission.signature_version} signature verified successfully."
        )
    else:
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='DSA_VERIFY_FAILED',
            ip_address=ip,
            quiz=submission.quiz,
            submission=submission,
            status='TAMPER_ALERT',
            details=f"DSA verification failed for submission ID {submission.id}!"
        )
        notify_instructor_dsa_failure(submission)

    # Respect Results Release status
    results_released = submission.quiz.results_released

    question_reviews = []
    if results_released:
        questions = submission.quiz.questions.all().order_by('id')
        submitted_answers = submission.answers or {}

        for q in questions:
            student_ans = submitted_answers.get(str(q.id), '')
            if q.question_type == 'ID':
                is_correct = bool(student_ans and student_ans.strip().lower() == q.correct_answer.strip().lower())
            elif q.question_type == 'TF':
                is_correct = bool(student_ans and student_ans.strip().capitalize() == q.correct_answer.strip().capitalize())
            else:  # MCQ
                is_correct = bool(student_ans and student_ans.strip().upper() == q.correct_answer.strip().upper())

            question_reviews.append({
                'question': q,
                'student_answer': student_ans,
                'is_correct': is_correct,
            })

    return render(request, 'quiz/quiz_result.html', {
        'submission': submission,
        'quiz': submission.quiz,
        'total_questions': submission.quiz.questions.count(),
        'is_dsa_valid': is_dsa_valid,
        'results_released': results_released,
        'question_reviews': question_reviews,
    })


@student_required
def student_profile(request):
    """
    Renders the student profile page, account security status, and completed exams history.
    """
    profile, _ = StudentProfile.objects.get_or_create(
        user=request.user,
        defaults={'full_name': request.user.get_full_name() or request.user.username, 'student_id': 'N/A'}
    )
    submissions = QuizSubmission.objects.filter(student=request.user).select_related('quiz').order_by('-submitted_at')
    active_session = ActiveSession.objects.filter(user=request.user).first()

    return render(request, 'quiz/student_profile.html', {
        'profile': profile,
        'submissions': submissions,
        'active_session': active_session,
    })


# ==============================================================================
# Instructor Views & Management
# ==============================================================================

@instructor_required
def instructor_dashboard(request):
    quizzes = Quiz.objects.filter(
        created_by=request.user
    ).order_by('-created_at')

    return render(request, 'quiz/instructor_dashboard.html', {
        'quizzes': quizzes
    })


@instructor_required
def toggle_quiz_status(request, quiz_id):
    """
    Toggles a quiz between Active (visible to students) and Inactive.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)
    if quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    if request.method == 'POST':
        quiz.is_active = not quiz.is_active
        quiz.save(update_fields=['is_active'])

        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='QUIZ_STATUS_TOGGLED',
            ip_address=get_client_ip(request),
            quiz=quiz,
            status='UPDATED',
            details=f"Quiz '{quiz.title}' set to {'Active' if quiz.is_active else 'Inactive'}."
        )
        messages.success(request, f"Quiz '{quiz.title}' is now {'Active' if quiz.is_active else 'Inactive'}.")

    return redirect('instructor_dashboard')


@instructor_required
def toggle_quiz_results(request, quiz_id):
    """
    Toggles whether quiz results, scores, and answer reviews are released to students.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)
    if quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    if request.method == 'POST':
        quiz.results_released = not quiz.results_released
        quiz.save(update_fields=['results_released'])

        action_name = 'RESULTS_RELEASED' if quiz.results_released else 'RESULTS_HIDDEN'
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action=action_name,
            ip_address=get_client_ip(request),
            quiz=quiz,
            status='UPDATED',
            details=f"Results for '{quiz.title}' were {'Released' if quiz.results_released else 'Hidden'}."
        )

        if quiz.results_released:
            notify_students_results_released(quiz)
            messages.success(request, f"Results for '{quiz.title}' released! Students have been notified.")
        else:
            messages.info(request, f"Results for '{quiz.title}' are now hidden from students.")

    return redirect('instructor_dashboard')


@instructor_required
def instructor_quiz_results(request, quiz_id):
    """
    Displays the quiz results, detailed analytics, most frequently missed questions,
    and individual student submission records with DSA verification.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)

    if quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    submissions = QuizSubmission.objects.filter(
        quiz=quiz
    ).select_related('student', 'student__student_profile').order_by('-submitted_at')

    submissions_with_status = []
    for sub in submissions:
        timestamp_str = sub.submitted_at.isoformat()
        is_valid = verify_dsa_signature(
            student_username=sub.student.username,
            quiz_id=quiz.id,
            score=sub.score,
            percentage=sub.percentage,
            timestamp_str=timestamp_str,
            hex_signature=sub.dsa_signature,
            answers=sub.answers,
            signature_version=sub.signature_version
        )
        submissions_with_status.append({
            'submission': sub,
            'is_dsa_valid': is_valid,
        })

    total_submissions = len(submissions_with_status)
    unique_students = len(set(sub['submission'].student_id for sub in submissions_with_status))
    questions = quiz.questions.all().order_by('id')
    total_questions = questions.count()

    if total_submissions > 0:
        percentages = [s['submission'].percentage for s in submissions_with_status]
        avg_percentage = round(sum(percentages) / total_submissions, 1)
        pass_count = sum(1 for s in submissions_with_status if s['submission'].is_passed)
        fail_count = total_submissions - pass_count
        pass_rate = round((pass_count / total_submissions) * 100.0, 1)
        fail_rate = round((fail_count / total_submissions) * 100.0, 1)
        highest_score = max(percentages)
        lowest_score = min(percentages)

        # Analysis of most frequently answered incorrectly questions
        question_stats = []
        for q in questions:
            incorrect_count = 0
            for s in submissions_with_status:
                ans = s['submission'].answers.get(str(q.id), '')
                is_corr = False
                if q.question_type == 'ID':
                    is_corr = bool(ans and ans.strip().lower() == q.correct_answer.strip().lower())
                elif q.question_type == 'TF':
                    is_corr = bool(ans and ans.strip().capitalize() == q.correct_answer.strip().capitalize())
                else:  # MCQ
                    is_corr = bool(ans and ans.strip().upper() == q.correct_answer.strip().upper())
                if not is_corr:
                    incorrect_count += 1

            error_rate = round((incorrect_count / total_submissions) * 100.0, 1)
            question_stats.append({
                'question': q,
                'incorrect_count': incorrect_count,
                'error_rate': error_rate
            })

        # Sort top missed questions descending
        question_stats.sort(key=lambda x: x['error_rate'], reverse=True)
        top_missed_questions = [qs for qs in question_stats if qs['incorrect_count'] > 0][:5]

    else:
        avg_percentage = None
        pass_rate = None
        fail_rate = None
        highest_score = None
        lowest_score = None
        top_missed_questions = []

    AuditLog.objects.create(
        actor=request.user,
        actor_username=request.user.username,
        action='QUIZ_EDITED',
        ip_address=get_client_ip(request),
        quiz=quiz,
        status='VIEWED',
        details=f"Instructor viewed results dashboard for '{quiz.title}'."
    )

    return render(request, 'quiz/instructor_quiz_results.html', {
        'quiz': quiz,
        'submissions_with_status': submissions_with_status,
        'total_submissions': total_submissions,
        'unique_students': unique_students,
        'total_questions': total_questions,
        'avg_percentage': avg_percentage,
        'pass_rate': pass_rate,
        'fail_rate': fail_rate,
        'highest_score': highest_score,
        'lowest_score': lowest_score,
        'top_missed_questions': top_missed_questions,
    })


@instructor_required
def export_quiz_results(request, quiz_id):
    """
    Exports quiz results to CSV (Excel-compatible with UTF-8 BOM).
    Restricted to the instructor who owns the quiz.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)
    if quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    submissions = QuizSubmission.objects.filter(
        quiz=quiz
    ).select_related('student', 'student__student_profile').order_by('-submitted_at')

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{quiz.title.replace(" ", "_")}_results.csv"'
    response.write('\ufeff')  # UTF-8 BOM for Microsoft Excel

    writer = csv.writer(response)
    writer.writerow([
        'Student Full Name',
        'Student ID',
        'Username',
        'Quiz Title',
        'Score',
        'Total Questions',
        'Percentage (%)',
        'Passing Grade (%)',
        'Result',
        'Submission Timestamp (UTC)',
        'Signature Version',
        'DSA Verification Status'
    ])

    total_q = quiz.questions.count()

    for sub in submissions:
        prof = getattr(sub.student, 'student_profile', None)
        full_name = prof.full_name if prof else sub.student.get_full_name() or sub.student.username
        student_id_val = prof.student_id if prof else 'N/A'

        timestamp_str = sub.submitted_at.isoformat()
        is_valid = verify_dsa_signature(
            student_username=sub.student.username,
            quiz_id=quiz.id,
            score=sub.score,
            percentage=sub.percentage,
            timestamp_str=timestamp_str,
            hex_signature=sub.dsa_signature,
            answers=sub.answers,
            signature_version=sub.signature_version
        )

        writer.writerow([
            full_name,
            student_id_val,
            sub.student.username,
            quiz.title,
            sub.score,
            total_q,
            f"{sub.percentage:.2f}",
            f"{quiz.passing_percentage:.2f}",
            "PASSED" if sub.is_passed else "FAILED",
            sub.submitted_at.strftime("%Y-%m-%d %H:%M:%S"),
            f"Version {sub.signature_version}",
            "VERIFIED" if is_valid else "TAMPERED / INVALID"
        ])

    AuditLog.objects.create(
        actor=request.user,
        actor_username=request.user.username,
        action='RESULTS_EXPORTED',
        ip_address=get_client_ip(request),
        quiz=quiz,
        status='EXPORTED',
        details=f"Exported {submissions.count()} submission records for '{quiz.title}' to CSV."
    )

    return response


@instructor_required
def instructor_submission_detail(request, submission_id):
    """
    Renders individual student submission review for instructors with DSA verification.
    """
    submission = get_object_or_404(
        QuizSubmission.objects.select_related('quiz', 'student', 'student__student_profile'),
        id=submission_id
    )

    if submission.quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    timestamp_str = submission.submitted_at.isoformat()
    is_dsa_valid = verify_dsa_signature(
        student_username=submission.student.username,
        quiz_id=submission.quiz.id,
        score=submission.score,
        percentage=submission.percentage,
        timestamp_str=timestamp_str,
        hex_signature=submission.dsa_signature,
        answers=submission.answers,
        signature_version=submission.signature_version
    )

    questions = submission.quiz.questions.all().order_by('id')
    total_questions = questions.count()
    submitted_answers = submission.answers or {}

    question_reviews = []
    for q in questions:
        student_ans = submitted_answers.get(str(q.id), '')
        if q.question_type == 'ID':
            is_correct = bool(student_ans and student_ans.strip().lower() == q.correct_answer.strip().lower())
        elif q.question_type == 'TF':
            is_correct = bool(student_ans and student_ans.strip().capitalize() == q.correct_answer.strip().capitalize())
        else:  # MCQ
            is_correct = bool(student_ans and student_ans.strip().upper() == q.correct_answer.strip().upper())

        question_reviews.append({
            'question': q,
            'student_answer': student_ans,
            'is_correct': is_correct,
        })

    return render(request, 'quiz/instructor_submission_detail.html', {
        'submission': submission,
        'quiz': submission.quiz,
        'student': submission.student,
        'question_reviews': question_reviews,
        'total_questions': total_questions,
        'is_dsa_valid': is_dsa_valid,
    })


@instructor_required
def security_logs(request):
    """
    Displays the centralized system audit trail and login monitoring events.
    Restricted to authorized instructors and administrators.
    """
    audit_records = AuditLog.objects.select_related('quiz', 'actor').order_by('-timestamp')[:200]
    security_records = SecurityLog.objects.order_by('-timestamp')[:200]

    return render(request, 'quiz/security_logs.html', {
        'audit_records': audit_records,
        'security_records': security_records,
    })


# ==============================================================================
# Quiz Management (Create & Edit)
# ==============================================================================

def _parse_indexed_questions(post_data):
    questions = []
    indices = set()
    for key in post_data.keys():
        if key.startswith('question_text_'):
            parts = key.split('_')
            if len(parts) >= 3 and parts[-1].isdigit():
                indices.add(int(parts[-1]))

    for idx in sorted(indices):
        qid = post_data.get(f'question_id_{idx}') or post_data.get(f'id_{idx}')
        try:
            qid = int(qid) if qid is not None else None
        except (ValueError, TypeError):
            qid = None

        questions.append({
            'id': qid,
            'question_text': post_data.get(f'question_text_{idx}', ''),
            'question_type': post_data.get(f'question_type_{idx}', 'MCQ'),
            'option_a': post_data.get(f'option_a_{idx}', ''),
            'option_b': post_data.get(f'option_b_{idx}', ''),
            'option_c': post_data.get(f'option_c_{idx}', ''),
            'option_d': post_data.get(f'option_d_{idx}', ''),
            'correct_answer': post_data.get(f'correct_answer_{idx}', '')
        })

    return questions


@instructor_required
def create_quiz(request):
    """
    Creates a new quiz with atomic transaction and validation.
    """
    if request.method == 'POST':
        form = QuizForm(request.POST)
        questions_json = request.POST.get('questions_data')
        raw_questions = []
        if questions_json:
            try:
                raw_questions = json.loads(questions_json)
            except (json.JSONDecodeError, TypeError):
                messages.error(request, "Invalid questions format submitted.")
        else:
            raw_questions = _parse_indexed_questions(request.POST)

        validated_questions, question_errors = validate_questions_data(raw_questions)

        if form.is_valid() and not question_errors:
            try:
                with transaction.atomic():
                    quiz = form.save(commit=False)
                    quiz.created_by = request.user
                    quiz.save()

                    for q_data in validated_questions:
                        Question.objects.create(
                            quiz=quiz,
                            question_text=q_data['question_text'],
                            question_type=q_data['question_type'],
                            option_a=q_data.get('option_a'),
                            option_b=q_data.get('option_b'),
                            option_c=q_data.get('option_c'),
                            option_d=q_data.get('option_d'),
                            correct_answer=q_data['correct_answer']
                        )

                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='QUIZ_CREATED',
                        ip_address=get_client_ip(request),
                        quiz=quiz,
                        status='CREATED',
                        details=f"Quiz '{quiz.title}' created with {len(validated_questions)} question(s)."
                    )

                messages.success(
                    request,
                    f"Quiz '{quiz.title}' with {len(validated_questions)} question(s) was created successfully!"
                )
                return redirect('instructor_dashboard')

            except Exception as e:
                messages.error(
                    request,
                    f"An error occurred while saving the quiz: {str(e)}. All changes have been rolled back."
                )
        else:
            for err in question_errors:
                messages.error(request, err)

    else:
        initial_pin = generate_secure_pin()
        form = QuizForm(initial={
            'access_pin': initial_pin,
            'time_limit_minutes': 15,
            'passing_percentage': 50.0,
            'is_active': True,
        })
        raw_questions = []

    return render(request, 'quiz/create_quiz.html', {
        'form': form,
        'existing_questions_json': json.dumps(raw_questions) if raw_questions else '[]'
    })


@instructor_required
def edit_quiz(request, quiz_id):
    """
    Allows instructors to edit an existing quiz and questions with ownership check.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)

    if quiz.created_by != request.user:
        return render(request, 'quiz/403.html', {'required_roles': ['Quiz Owner']}, status=403)

    if request.method == 'POST':
        form = QuizForm(request.POST, instance=quiz)
        questions_json = request.POST.get('questions_data')
        raw_questions = []
        if questions_json:
            try:
                raw_questions = json.loads(questions_json)
            except (json.JSONDecodeError, TypeError):
                messages.error(request, "Invalid questions format submitted.")
        else:
            raw_questions = _parse_indexed_questions(request.POST)

        validated_questions, question_errors = validate_questions_data(raw_questions)

        if form.is_valid() and not question_errors:
            try:
                with transaction.atomic():
                    quiz = form.save()
                    existing_questions_map = {q.id: q for q in quiz.questions.all()}
                    keep_ids = set()

                    for q_data in validated_questions:
                        qid = q_data.get('id')
                        try:
                            qid = int(qid) if qid is not None else None
                        except (ValueError, TypeError):
                            qid = None

                        if qid and qid in existing_questions_map:
                            q_obj = existing_questions_map[qid]
                            q_obj.question_text = q_data['question_text']
                            q_obj.question_type = q_data['question_type']
                            q_obj.option_a = q_data.get('option_a')
                            q_obj.option_b = q_data.get('option_b')
                            q_obj.option_c = q_data.get('option_c')
                            q_obj.option_d = q_data.get('option_d')
                            q_obj.correct_answer = q_data['correct_answer']
                            q_obj.save()
                            keep_ids.add(qid)
                        else:
                            new_q = Question.objects.create(
                                quiz=quiz,
                                question_text=q_data['question_text'],
                                question_type=q_data['question_type'],
                                option_a=q_data.get('option_a'),
                                option_b=q_data.get('option_b'),
                                option_c=q_data.get('option_c'),
                                option_d=q_data.get('option_d'),
                                correct_answer=q_data['correct_answer']
                            )
                            keep_ids.add(new_q.id)

                    for qid, q_obj in existing_questions_map.items():
                        if qid not in keep_ids:
                            q_obj.delete()

                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='QUIZ_EDITED',
                        ip_address=get_client_ip(request),
                        quiz=quiz,
                        status='UPDATED',
                        details=f"Quiz '{quiz.title}' updated with {len(validated_questions)} question(s)."
                    )

                messages.success(
                    request,
                    f"Quiz '{quiz.title}' with {len(validated_questions)} question(s) was updated successfully!"
                )
                return redirect('instructor_dashboard')

            except Exception as e:
                messages.error(
                    request,
                    f"An error occurred while updating the quiz: {str(e)}. All changes have been rolled back."
                )
        else:
            for err in question_errors:
                messages.error(request, err)

    else:
        form = QuizForm(instance=quiz)

    existing_questions = [
        {
            'id': q.id,
            'question_text': q.question_text,
            'question_type': q.question_type,
            'option_a': q.option_a or '',
            'option_b': q.option_b or '',
            'option_c': q.option_c or '',
            'option_d': q.option_d or '',
            'correct_answer': q.correct_answer or ''
        }
        for q in quiz.questions.all().order_by('id')
    ]

    return render(request, 'quiz/edit_quiz.html', {
        'form': form,
        'quiz': quiz,
        'existing_questions_json': json.dumps(existing_questions)
    })
