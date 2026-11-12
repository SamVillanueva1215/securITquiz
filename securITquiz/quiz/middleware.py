"""
securITquiz - Single Active Session & Security Middleware
Enforces single active session for Student accounts and configurable inactivity timeout.
"""

import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse
from django.urls import Resolver404, resolve, reverse
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.contrib.auth import logout as auth_logout
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.sessions.models import Session
from .models import (
    ActiveSession,
    AuditLog,
    QuizAttempt,
    QuizSubmission,
    SecurityLog,
    get_session_inactivity_timeout_seconds,
)


_PASSIVE_POLL_URL_NAMES = frozenset({
    'pending_device_request',
    'check_approval_status',
})

_JSON_ONLY_URL_NAMES = frozenset({
    'save_quiz_progress',
    'pending_device_request',
    'check_approval_status',
})


def is_ajax_request(request):
    """
    Returns True for fetch/XHR JSON requests and JSON-only endpoints so auth/session
    failures return explicit JSON rather than HTML login redirects.
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept and 'text/html' not in accept:
        return True
    try:
        match = resolve(request.path_info)
        return match.url_name in _JSON_ONLY_URL_NAMES
    except Resolver404:
        return False


def _get_inactivity_timeout_label():
    seconds = get_session_inactivity_timeout_seconds()
    if seconds >= 60 and seconds % 60 == 0:
        mins = seconds // 60
        return f"{mins} minute" if mins == 1 else f"{mins} minutes"
    return f"{seconds} seconds"


def get_client_ip(request):
    """Retrieves client IP address reliably from HTTP headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def get_or_create_device_id(request):
    """
    Retrieves or generates a unique server-issued device identifier from a secure cookie or session.
    Guarantees device identification independent of easily modified browser user-agent strings.
    """
    device_id = request.COOKIES.get('securit_device_id')
    if not device_id and hasattr(request, 'session'):
        device_id = request.session.get('device_id')
    if not device_id:
        device_id = uuid.uuid4().hex
    return device_id


def is_student_session_enforced(user):
    """
    Single-active-session enforcement applies strictly to Student accounts.
    Instructors and Administrators are permitted concurrent sessions.
    """
    if not user or not user.is_authenticated:
        return False
    user_roles = set(user.groups.values_list('name', flat=True))
    is_student = 'Student' in user_roles
    is_privileged = bool({'Instructor', 'Administrator'} & user_roles) or user.is_superuser
    return is_student and not is_privileged


def purge_stale_active_session(
    user,
    active_session,
    ip_address='127.0.0.1',
    action='SESSION_EXPIRED',
    status='EXPIRED',
    details='Session automatically expired due to inactivity.',
):
    """
    Removes a stale, expired, deleted, or invalidated ActiveSession record and
    logs the corresponding security and audit trail events without exposing session keys.
    """
    AuditLog.objects.create(
        actor=user,
        actor_username=user.username,
        action=action,
        ip_address=ip_address,
        status=status,
        details=details,
    )
    SecurityLog.objects.create(
        username_attempted=user.username,
        ip_address=ip_address,
        is_success=False,
        action=action,
    )
    Session.objects.filter(session_key=active_session.session_key).delete()
    active_session.delete()


def is_active_session_live(user, active_session, ip_address='127.0.0.1'):
    """
    Verifies whether an ActiveSession record corresponds to a genuinely live,
    unexpired, non-invalidated Django session for `user`.
    Automatically purges stale, deleted, expired, or password-invalidated records.
    """
    if not active_session:
        return False

    if active_session.is_expired():
        purge_stale_active_session(
            user=user,
            active_session=active_session,
            ip_address=ip_address,
            action='SESSION_EXPIRED',
            status='EXPIRED',
            details=f"Session automatically expired after {_get_inactivity_timeout_label()} of inactivity.",
        )
        return False

    django_session = Session.objects.filter(session_key=active_session.session_key).first()
    if not django_session or django_session.expire_date <= timezone.now():
        purge_stale_active_session(
            user=user,
            active_session=active_session,
            ip_address=ip_address,
            action='SESSION_EXPIRED',
            status='EXPIRED',
            details="Prior session expired or was removed from the session store.",
        )
        return False

    try:
        decoded = django_session.get_decoded()
    except Exception:
        purge_stale_active_session(
            user=user,
            active_session=active_session,
            ip_address=ip_address,
            action='SESSION_REVOKED',
            status='INVALID',
            details="Prior session payload was invalid or corrupted.",
        )
        return False

    if str(decoded.get('_auth_user_id', '')) != str(user.pk):
        purge_stale_active_session(
            user=user,
            active_session=active_session,
            ip_address=ip_address,
            action='SESSION_REVOKED',
            status='INVALID',
            details="Prior session user binding was invalid.",
        )
        return False

    expected_hash = user.get_session_auth_hash()
    session_hash = decoded.get('_auth_user_hash', '')
    if expected_hash and not constant_time_compare(str(session_hash), str(expected_hash)):
        purge_stale_active_session(
            user=user,
            active_session=active_session,
            ip_address=ip_address,
            action='SESSION_REVOKED',
            status='INVALID',
            details="Prior session was invalidated due to password or credential change.",
        )
        return False

    return True


def cleanup_expired_sessions(user=None, ip_address='127.0.0.1'):
    """
    Cleans up stale, expired, deleted, or invalidated ActiveSession records
    and logs SESSION_EXPIRED / SESSION_REVOKED audit events.
    """
    qs = ActiveSession.objects.select_related('user').all()
    if user:
        qs = qs.filter(user=user)

    for active in list(qs):
        is_active_session_live(active.user, active, ip_address=ip_address)


def _is_passive_poll_request(request):
    try:
        match = resolve(request.path_info)
        return match.url_name in _PASSIVE_POLL_URL_NAMES
    except Resolver404:
        return False


def _preserve_expired_quiz_draft(request, user):
    """
    Preserves non-locked quiz answers if a Student's active session expires
    just before a CSRF-validated quiz POST, without bypassing re-authentication
    or finalizing/grading the submission on an expired session.
    """
    if request.method != 'POST':
        return None
    try:
        match = resolve(request.path_info)
    except Resolver404:
        return None
    if match.url_name not in ('take_quiz', 'save_quiz_progress'):
        return None

    quiz_id = match.kwargs.get('quiz_id')
    if not quiz_id:
        return None

    has_pin = bool(
        request.session.get(f'pin_verified_quiz_{quiz_id}')
        or request.session.get(f'verified_quiz_{quiz_id}_user_{user.id}')
    )
    if not has_pin:
        return None

    now = timezone.now()
    try:
        with transaction.atomic():
            attempt = QuizAttempt.objects.select_for_update().filter(
                student=user,
                quiz_id=quiz_id,
                is_completed=False
            ).first()
            if not attempt:
                return None

            quiz = attempt.quiz
            if not quiz.is_active:
                return None

            if QuizSubmission.objects.filter(student=user, quiz_id=quiz_id).exists():
                return None

            if quiz.deadline and now > quiz.deadline:
                return None
            if attempt.deadline and now > attempt.deadline:
                return None

            attempt.save_answers_from_post(request.POST)
            return quiz_id
    except ValidationError:
        return None


class SingleActiveSessionMiddleware:
    """
    Middleware that enforces single-active-session protection and configurable
    inactivity expiration (`SESSION_INACTIVITY_TIMEOUT`) for Student accounts,
    while issuing secure server-side device identifiers.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        device_id = get_or_create_device_id(request)
        request.device_id = device_id
        if hasattr(request, 'session') and request.session.get('device_id') != device_id:
            request.session['device_id'] = device_id

        if request.user.is_authenticated and is_student_session_enforced(request.user):
            session_key = request.session.session_key
            if not session_key:
                request.session.save()
                session_key = request.session.session_key

            active_session = ActiveSession.objects.filter(user=request.user).first()
            now = timezone.now()

            if active_session:
                # 1. Reject any session key that does not match the active Student session
                if active_session.session_key != session_key:
                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='SESSION_REVOKED',
                        ip_address=get_client_ip(request),
                        device_id=device_id,
                        status='REVOKED',
                        details="Session terminated because it does not match the active student session."
                    )
                    SecurityLog.objects.create(
                        username_attempted=request.user.username,
                        ip_address=get_client_ip(request),
                        is_success=False,
                        action='SESSION_REVOKED'
                    )
                    auth_logout(request)
                    if is_ajax_request(request):
                        return JsonResponse({
                            'status': 'session_revoked',
                            'preserved': False,
                            'message': (
                                "Your session was terminated because it is no longer the active session. "
                                "Latest changes could not be saved."
                            ),
                            'login_url': reverse('login'),
                        }, status=401)
                    messages.warning(
                        request,
                        "Your session was terminated because it is no longer the active session."
                    )
                    return redirect('login')

                # 2. Check configured inactivity timeout
                if active_session.is_expired():
                    preserved_quiz_id = _preserve_expired_quiz_draft(request, request.user)
                    timeout_label = _get_inactivity_timeout_label()
                    details = f"Session automatically expired after {timeout_label} of inactivity."
                    if preserved_quiz_id is not None:
                        details += " In-progress quiz draft answers were preserved for recovery."
                    purge_stale_active_session(
                        user=request.user,
                        active_session=active_session,
                        ip_address=get_client_ip(request),
                        action='SESSION_EXPIRED',
                        status='EXPIRED',
                        details=details,
                    )
                    auth_logout(request)
                    if is_ajax_request(request):
                        if preserved_quiz_id is not None:
                            next_url = reverse('verify_quiz_pin', kwargs={'quiz_id': preserved_quiz_id})
                            return JsonResponse({
                                'status': 'session_expired',
                                'preserved': True,
                                'quiz_id': preserved_quiz_id,
                                'message': (
                                    "Your session expired due to inactivity, but your latest in-progress quiz "
                                    "answers were preserved. Please log in again and verify the quiz PIN to resume and submit."
                                ),
                                'login_url': f"{reverse('login')}?next={next_url}",
                            }, status=401)
                        return JsonResponse({
                            'status': 'session_expired',
                            'preserved': False,
                            'message': (
                                f"Your session expired due to {timeout_label} of inactivity, and these latest "
                                "changes could not be preserved automatically. Please log in again."
                            ),
                            'login_url': reverse('login'),
                        }, status=401)
                    if preserved_quiz_id is not None:
                        messages.info(
                            request,
                            "Your session expired due to inactivity, but your in-progress quiz answers were safely saved. "
                            "Please log in again and verify the quiz PIN to resume and submit."
                        )
                        next_url = reverse('verify_quiz_pin', kwargs={'quiz_id': preserved_quiz_id})
                        return redirect(f"{reverse('login')}?next={next_url}")

                    messages.info(
                        request,
                        f"Your session has expired due to {timeout_label} of inactivity. Please log in again."
                    )
                    return redirect('login')

                # 3. Meaningful activity only: background polling never extends student activity
                if not _is_passive_poll_request(request):
                    if (now - active_session.last_activity).total_seconds() > 30:
                        active_session.last_activity = now
                        if active_session.device_id != device_id:
                            active_session.device_id = device_id
                            active_session.save(update_fields=['last_activity', 'device_id'])
                        else:
                            active_session.save(update_fields=['last_activity'])

            else:
                # Create active session record if authenticated directly (e.g. test force_login)
                ActiveSession.objects.get_or_create(
                    user=request.user,
                    defaults={
                        'session_key': session_key,
                        'device_id': device_id,
                        'ip_address': get_client_ip(request),
                        'last_activity': now,
                    }
                )

        # Slide Django session cookie expiry only for authenticated meaningful requests
        # (never passive polling), replacing global SESSION_SAVE_EVERY_REQUEST = True.
        if (
            request.user.is_authenticated
            and hasattr(request, 'session')
            and not _is_passive_poll_request(request)
        ):
            request.session.modified = True

        response = self.get_response(request)

        # Securely issue and persist the server-issued device identifier
        if not request.COOKIES.get('securit_device_id') or request.COOKIES.get('securit_device_id') != device_id:
            response.set_cookie(
                'securit_device_id',
                device_id,
                max_age=365 * 24 * 3600,
                httponly=True,
                samesite='Lax',
                secure=not settings.DEBUG
            )

        return response
