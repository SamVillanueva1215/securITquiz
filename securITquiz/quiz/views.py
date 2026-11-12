import csv
import json
import random
import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.contrib.auth.decorators import login_required

from .models import (
    Quiz,
    QuizSubmission,
    Question,
    StudentProfile,
    InstructorProfile,
    ActiveSession,
    DeviceAuthorizationRequest,
    QuizAttempt,
    SecurityLog,
    AuditLog
)
from .forms import (
    StudentRegistrationForm,
    InstructorRegistrationForm,
    EmailOrUsernameAuthenticationForm,
    QuizForm,
    PinVerificationForm,
    validate_questions_data,
    generate_secure_pin
)
from .decorators import student_required, instructor_required, admin_required
from .crypto import generate_dsa_signature, verify_dsa_signature
from .middleware import (
    get_client_ip,
    cleanup_expired_sessions,
    get_or_create_device_id,
    is_student_session_enforced,
    is_active_session_live,
)
from .notifications import (
    notify_student_submission_confirmation,
    notify_instructor_new_submission,
    notify_instructor_dsa_failure,
    notify_students_results_released,
    notify_suspicious_security_event,
    notify_device_auth_requested,
    notify_device_auth_approved,
    notify_device_auth_denied,
    notify_device_auth_expired,
)


# ==============================================================================
# Public Views & Authentication
# ==============================================================================

_FORBIDDEN_PUBLIC_ROLES = {
    'admin',
    'administrator',
    'superadmin',
    'superuser',
    'staff',
    'root',
}
_ROLE_PARAM_KEYS = (
    'role',
    'group',
    'groups',
    'account_type',
    'user_type',
)
_FLAG_PARAM_KEYS = (
    'is_staff',
    'is_superuser',
    'is_active',
    'permissions',
    'user_permissions',
)


def _check_public_admin_registration_attempt(request):
    """
    Detects manipulated query or POST parameters attempting to submit
    privileged roles, group overrides, or staff/superuser/permission flags.
    """
    if request.method == 'POST':
        for key in _ROLE_PARAM_KEYS + _FLAG_PARAM_KEYS:
            if key in request.POST:
                return True

    for key in _ROLE_PARAM_KEYS:
        val = request.GET.get(key, '').strip().lower()
        if val in _FORBIDDEN_PUBLIC_ROLES:
            return True
    for key in _FLAG_PARAM_KEYS:
        if key in request.GET:
            return True
    return False


def _render_forbidden_admin_registration(request, reason='Public Administrator registration is strictly prohibited.'):
    AuditLog.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        actor_username=request.user.username if request.user.is_authenticated else 'anonymous',
        action='UNAUTHORIZED_ACCESS_ATTEMPT',
        ip_address=get_client_ip(request),
        status='BLOCKED',
        details=f"Blocked unauthorized registration attempt: {reason}"
    )
    return render(
        request,
        'quiz/403.html',
        {
            'required_roles': ['Unauthenticated Public Visitor'],
            'user_roles': (
                list(request.user.groups.values_list('name', flat=True))
                if request.user.is_authenticated else ['Public Visitor']
            ),
            'denial_reason': reason,
        },
        status=403
    )


def _get_role_landing_url(user):
    if user.groups.filter(name='Instructor').exists():
        return reverse('instructor_dashboard')
    if user.groups.filter(name='Administrator').exists() or user.is_superuser:
        return reverse('security_logs')
    return reverse('student_dashboard')


def _get_safe_redirect_target(request, user):
    """
    Returns a validated local redirect URL if `next` is trusted, or falls
    back to the user's authoritative role landing URL. Prevents open redirects.
    """
    landing_url = _get_role_landing_url(user)

    # Unapproved instructors always go to instructor_dashboard (denied 403)
    if user.groups.filter(name='Instructor').exists():
        profile = getattr(user, 'instructor_profile', None)
        if not profile or not profile.is_authorized():
            return reverse('instructor_dashboard')

    next_url = (request.POST.get('next') or request.GET.get('next') or '').strip()
    if next_url and url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return next_url

    return landing_url


def home(request):
    return render(request, 'quiz/index.html')


def register(request):
    """
    Public student registration endpoint.
    Preserves existing student registration functionality.
    Guards against unauthorized public administrator registration attempts
    and blocks authenticated users from creating extra accounts or changing roles.
    """
    if _check_public_admin_registration_attempt(request):
        return _render_forbidden_admin_registration(request)

    if request.user.is_authenticated:
        if request.method == 'POST':
            return _render_forbidden_admin_registration(
                request,
                reason='Authenticated users cannot register additional accounts or modify roles.'
            )
        return redirect(_get_role_landing_url(request.user))

    role_requested = request.GET.get('role', '').strip().lower()
    if role_requested == 'instructor':
        return redirect('register_instructor')

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
        'form': form,
        'registration_type': 'student',
    })


def register_instructor(request):
    """
    Public instructor registration endpoint.
    Newly registered instructors automatically receive an InstructorProfile with PENDING status.
    Guards against unauthorized public administrator registration attempts
    and blocks authenticated users from creating extra accounts or changing roles.
    """
    if _check_public_admin_registration_attempt(request):
        return _render_forbidden_admin_registration(request)

    if request.user.is_authenticated:
        if request.method == 'POST':
            return _render_forbidden_admin_registration(
                request,
                reason='Authenticated users cannot register additional accounts or modify roles.'
            )
        return redirect(_get_role_landing_url(request.user))

    if request.method == 'POST':
        form = InstructorRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            ip = get_client_ip(request)
            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='INSTRUCTOR_REGISTERED',
                ip_address=ip,
                status='PENDING',
                details=f"Instructor account registered (Pending Approval): {user.username} ({user.email})"
            )
            messages.success(
                request,
                'Your instructor application has been submitted successfully and is pending administrator approval. '
                'You will not be able to access instructor features until an administrator approves your account.'
            )
            return redirect('login')
    else:
        form = InstructorRegistrationForm()

    return render(request, 'quiz/register_instructor.html', {
        'form': form,
        'registration_type': 'instructor',
    })


def _reject_duplicate_student_login(request, form, user, ip, device_id):
    """
    Records security/audit events for a rejected duplicate Student login
    without exposing passwords, hashes, or session keys, and re-renders login.
    """
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
        device_id=device_id,
        status='BLOCKED',
        details=f"Rejected duplicate Student login from IP {ip} while an active session already exists."
    )
    notify_suspicious_security_event(
        user=user,
        ip_address=ip,
        event_type="Blocked Duplicate Login Attempt",
        details=(
            f"A duplicate login attempt for your account was rejected from IP address {ip} "
            "because an active session is already open."
        )
    )
    err_msg = (
        "This student account already has an active session on another device or browser. "
        "Please log out from your existing session before logging in again."
    )
    form.add_error(None, err_msg)
    messages.error(request, err_msg)
    next_url = (request.POST.get('next') or request.GET.get('next') or '').strip()
    return render(request, 'quiz/login.html', {'form': form, 'next': next_url})


def user_login(request):
    """
    Handles role-based authentication and Student-only Single-Active-Session Enforcement.
    - Students with a live active session on another browser/device have second logins rejected;
      the first session remains active and untouched.
    - Stale, expired, deleted, or password-invalidated Student sessions are automatically cleaned up.
    - Instructors and Administrators are permitted concurrent sessions across devices.
    - Untrusted `next` redirects are rejected to prevent open redirects.
    """
    if request.user.is_authenticated:
        return redirect(_get_safe_redirect_target(request, request.user))

    if request.method == 'POST':
        form = EmailOrUsernameAuthenticationForm(request, data=request.POST)
        ip = get_client_ip(request)

        if form.is_valid():
            user = form.get_user()
            is_student = user.groups.filter(name='Student').exists()
            is_instructor = user.groups.filter(name='Instructor').exists()
            is_admin = user.groups.filter(name='Administrator').exists() or user.is_superuser

            if not (is_student or is_instructor or is_admin):
                SecurityLog.objects.create(
                    username_attempted=user.username,
                    ip_address=ip,
                    is_success=False,
                    action='LOGIN_FAILED'
                )
                AuditLog.objects.create(
                    actor=user,
                    actor_username=user.username,
                    action='UNAUTHORIZED_ACCESS_ATTEMPT',
                    ip_address=ip,
                    status='DENIED',
                    details="Login blocked: account has no recognized securITquiz role."
                )
                err_msg = 'Your account does not have a valid securITquiz role.'
                form.add_error(None, err_msg)
                messages.error(request, err_msg)
                return render(request, 'quiz/login.html', {'form': form})

            device_id = get_or_create_device_id(request)
            enforce_single_session = is_student_session_enforced(user)

            if enforce_single_session:
                # Lock User row where supported (PostgreSQL) to serialize concurrent logins
                try:
                    with transaction.atomic():
                        if connection.features.has_select_for_update:
                            User.objects.select_for_update().get(pk=user.pk)
                            active_session = ActiveSession.objects.select_for_update().filter(user=user).first()
                        else:
                            active_session = ActiveSession.objects.filter(user=user).first()

                        if active_session and is_active_session_live(user, active_session, ip_address=ip):
                            if active_session.session_key != request.session.session_key:
                                return _reject_duplicate_student_login(request, form, user, ip, device_id)

                        # No live conflicting session: rotate/establish Django session & ActiveSession
                        login(request, user)
                        new_session_key = request.session.session_key
                        if not new_session_key:
                            request.session.save()
                            new_session_key = request.session.session_key

                        ActiveSession.objects.create(
                            user=user,
                            session_key=new_session_key,
                            device_id=device_id,
                            ip_address=ip,
                            last_activity=timezone.now()
                        )
                except IntegrityError:
                    # Defense-in-depth fallback (e.g. SQLite concurrent race on OneToOneField UNIQUE)
                    if request.user.is_authenticated:
                        logout(request)
                    return _reject_duplicate_student_login(request, form, user, ip, device_id)
            else:
                # Instructors and Administrators are not restricted by Student single-session lock
                with transaction.atomic():
                    login(request, user)
                    if not request.session.session_key:
                        request.session.save()

            with transaction.atomic():
                SecurityLog.objects.create(
                    username_attempted=user.username,
                    ip_address=ip,
                    is_success=True,
                    action='LOGIN_SUCCESS'
                )
                AuditLog.objects.create(
                    actor=user,
                    actor_username=user.username,
                    action='SESSION_CREATED',
                    ip_address=ip,
                    device_id=device_id,
                    status='CREATED',
                    details="New authenticated session created."
                )
                AuditLog.objects.create(
                    actor=user,
                    actor_username=user.username,
                    action='LOGIN_SUCCESS',
                    ip_address=ip,
                    device_id=device_id,
                    status='SUCCESS',
                    details="User logged in successfully."
                )

            return redirect(_get_safe_redirect_target(request, user))

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
        'form': form,
        'next': request.GET.get('next', ''),
    })


def waiting_for_approval(request):
    """
    Renders the Waiting for Approval screen on Device B while awaiting Device A's response.
    Device B remains unauthenticated during this phase.
    """
    if request.user.is_authenticated:
        return redirect(_get_role_landing_url(request.user))

    req_id = request.session.get('device_auth_request_id')
    if not req_id:
        return redirect('login')

    auth_req = DeviceAuthorizationRequest.objects.filter(
        id=req_id,
        requesting_session_key=request.session.session_key
    ).first()

    if not auth_req:
        request.session.pop('device_auth_request_id', None)
        request.session.pop('pending_user_id', None)
        request.session.pop('pending_backend', None)
        messages.error(request, "Authorization request not found. Please log in again.")
        return redirect('login')

    # Check for expiration
    auth_req.check_expiration()
    remaining_seconds = max(0, int((auth_req.expires_at - timezone.now()).total_seconds()))

    active_session = ActiveSession.objects.filter(user=auth_req.user).first()

    return render(request, 'quiz/waiting_for_approval.html', {
        'auth_req': auth_req,
        'remaining_seconds': remaining_seconds,
        'account_username': auth_req.user.username,
        'existing_ip': active_session.ip_address if active_session else 'Unknown',
    })


def check_approval_status(request):
    """
    JSON polling endpoint for Device B to check if Device A approved or denied the login request.
    Handles automatic promotion of Device B to active session upon approval.
    """
    req_id = request.session.get('device_auth_request_id')
    if not req_id:
        return JsonResponse({'status': 'NOT_FOUND', 'message': 'No pending authorization request.'})

    with transaction.atomic():
        auth_req = DeviceAuthorizationRequest.objects.select_for_update().filter(
            id=req_id,
            requesting_session_key=request.session.session_key
        ).first()

        if not auth_req:
            return JsonResponse({'status': 'NOT_FOUND', 'message': 'Request not found.'})

        now = timezone.now()

        # Check expiration
        if auth_req.status == 'PENDING' and auth_req.is_expired():
            auth_req.status = 'EXPIRED'
            auth_req.resolved_at = now
            auth_req.save(update_fields=['status', 'resolved_at'])

            AuditLog.objects.create(
                actor=auth_req.user,
                actor_username=auth_req.user.username,
                action='DEVICE_AUTHORIZATION_EXPIRED',
                ip_address=auth_req.requesting_ip,
                device_id=auth_req.requesting_device_id or '',
                status='EXPIRED',
                details=f"Device authorization request #{auth_req.id} timed out after 60 seconds without response."
            )
            AuditLog.objects.create(
                actor=auth_req.user,
                actor_username=auth_req.user.username,
                action='DEVICE_AUTH_EXPIRED',
                ip_address=auth_req.requesting_ip,
                device_id=auth_req.requesting_device_id or '',
                status='EXPIRED',
                details=f"Device authorization request #{auth_req.id} timed out after 60 seconds without response."
            )
            SecurityLog.objects.create(
                username_attempted=auth_req.user.username,
                ip_address=auth_req.requesting_ip,
                is_success=False,
                action='DEVICE_AUTH_EXPIRED'
            )
            notify_device_auth_expired(
                user=auth_req.user,
                requesting_ip=auth_req.requesting_ip
            )

        if auth_req.status == 'PENDING':
            remaining = max(0, int((auth_req.expires_at - now).total_seconds()))
            return JsonResponse({'status': 'PENDING', 'remaining_seconds': remaining})

        elif auth_req.status == 'DENIED':
            request.session.pop('device_auth_request_id', None)
            request.session.pop('pending_user_id', None)
            request.session.pop('pending_backend', None)
            return JsonResponse({
                'status': 'DENIED',
                'message': 'Login request was denied by the active device. Your login was cancelled.'
            })

        elif auth_req.status == 'EXPIRED':
            request.session.pop('device_auth_request_id', None)
            request.session.pop('pending_user_id', None)
            request.session.pop('pending_backend', None)
            return JsonResponse({
                'status': 'EXPIRED',
                'message': 'Login authorization request timed out after 1 minute without approval. Please log in again.'
            })

        elif auth_req.status == 'APPROVED':
            # Enforce Student single-active-session restriction: never allow promotion over live Student session
            user = auth_req.user
            if is_student_session_enforced(user):
                old_active = ActiveSession.objects.filter(user=user).first()
                if old_active and is_active_session_live(user, old_active, ip_address=get_client_ip(request)):
                    request.session.pop('device_auth_request_id', None)
                    request.session.pop('pending_user_id', None)
                    request.session.pop('pending_backend', None)
                    return JsonResponse({
                        'status': 'DENIED',
                        'message': 'Student account already has an active session.'
                    }, status=403)

            backend = request.session.get('pending_backend')
            user.backend = backend
            device_id = auth_req.requesting_device_id or get_or_create_device_id(request)

            # Invalidate old session in Django session database
            old_active = ActiveSession.objects.filter(user=user).first()
            if old_active:
                Session.objects.filter(session_key=old_active.session_key).delete()

            login(request, user)
            new_session_key = request.session.session_key
            if not new_session_key:
                request.session.save()
                new_session_key = request.session.session_key

            ActiveSession.objects.update_or_create(
                user=user,
                defaults={
                    'session_key': new_session_key,
                    'device_id': device_id,
                    'ip_address': auth_req.requesting_ip,
                    'last_activity': now
                }
            )

            # Invalidate any other pending requests for this user
            DeviceAuthorizationRequest.objects.filter(
                user=user,
                status='PENDING'
            ).exclude(id=auth_req.id).update(status='EXPIRED', resolved_at=now)

            SecurityLog.objects.create(
                username_attempted=user.username,
                ip_address=auth_req.requesting_ip,
                is_success=True,
                action='DEVICE_SWITCH_CONFIRMED'
            )
            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='DEVICE_AUTHORIZATION_TRANSFERRED',
                ip_address=auth_req.requesting_ip,
                device_id=device_id,
                status='TRANSFERRED',
                details=f"Device authorization completed. Authority transferred to Device B (IP {auth_req.requesting_ip})."
            )
            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='DEVICE_SWITCH_CONFIRMED',
                ip_address=auth_req.requesting_ip,
                device_id=device_id,
                status='CONFIRMED',
                details=f"Device authorization completed. Device B (IP {auth_req.requesting_ip}) is now the active session authority."
            )
            AuditLog.objects.create(
                actor=user,
                actor_username=user.username,
                action='SESSION_CREATED',
                ip_address=auth_req.requesting_ip,
                device_id=device_id,
                status='CREATED',
                details="Device B session established following mutual authorization."
            )

            # Clean up pending state
            request.session.pop('device_auth_request_id', None)
            request.session.pop('pending_user_id', None)
            request.session.pop('pending_backend', None)

            redirect_url = _get_role_landing_url(user)
            return JsonResponse({
                'status': 'APPROVED',
                'redirect_url': redirect_url
            })

    return JsonResponse({'status': 'UNKNOWN'})


def cancel_authorization_request(request):
    """
    Cancels pending authorization from Device B and redirects to login.
    """
    req_id = request.session.get('device_auth_request_id')
    ip = get_client_ip(request)

    if req_id:
        with transaction.atomic():
            auth_req = DeviceAuthorizationRequest.objects.select_for_update().filter(
                id=req_id,
                requesting_session_key=request.session.session_key
            ).first()

            if auth_req and auth_req.status == 'PENDING':
                auth_req.status = 'DENIED'
                auth_req.resolved_at = timezone.now()
                auth_req.save(update_fields=['status', 'resolved_at'])

                AuditLog.objects.create(
                    actor=auth_req.user,
                    actor_username=auth_req.user.username,
                    action='DEVICE_SWITCH_CANCELLED',
                    ip_address=ip,
                    status='CANCELLED',
                    details="Device authorization was cancelled by the requesting device."
                )
                SecurityLog.objects.create(
                    username_attempted=auth_req.user.username,
                    ip_address=ip,
                    is_success=False,
                    action='DEVICE_SWITCH_CANCELLED'
                )

    request.session.pop('device_auth_request_id', None)
    request.session.pop('pending_user_id', None)
    request.session.pop('pending_backend', None)
    messages.info(request, "Login request cancelled.")
    return redirect('login')


@login_required
def pending_device_request(request):
    """
    JSON endpoint polled by Device A (active session) to detect incoming login requests.
    Strictly verifies that only the currently active session receives requests.
    """
    active_session = ActiveSession.objects.filter(user=request.user).first()
    if not active_session or active_session.session_key != request.session.session_key:
        return JsonResponse({'has_request': False})

    now = timezone.now()
    pending = DeviceAuthorizationRequest.objects.filter(
        user=request.user,
        status='PENDING',
        expires_at__gt=now
    ).order_by('-created_at').first()

    if pending:
        remaining = max(0, int((pending.expires_at - now).total_seconds()))
        return JsonResponse({
            'has_request': True,
            'request_id': pending.id,
            'ip_address': pending.requesting_ip or 'Unknown',
            'user_agent': pending.requesting_user_agent or 'Unknown Device',
            'remaining_seconds': remaining
        })

    return JsonResponse({'has_request': False})


@login_required
def respond_device_request(request):
    """
    Handles Device A's Approve or Deny action on an incoming device login request.
    Security:
    - POST only, CSRF-protected.
    - Strictly checks that request.session.session_key == active_session.session_key.
    - Prevents expired or reused requests from being approved.
    - If approved, marks request APPROVED, records audit trails, and logs out Device A immediately.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'POST method required.'}, status=405)

    active_session = ActiveSession.objects.filter(user=request.user).first()
    if not active_session or active_session.session_key != request.session.session_key:
        return JsonResponse({
            'status': 'error',
            'message': 'Only the currently active session can approve or deny login requests.'
        }, status=403)

    try:
        data = json.loads(request.body) if request.content_type == 'application/json' else request.POST
        request_id = data.get('request_id')
        decision = data.get('decision')
    except Exception:
        return JsonResponse({'status': 'error', 'message': 'Invalid request payload.'}, status=400)

    if not request_id or decision not in ['approve', 'deny']:
        return JsonResponse({'status': 'error', 'message': 'Invalid parameters.'}, status=400)

    ip = get_client_ip(request)

    with transaction.atomic():
        auth_req = DeviceAuthorizationRequest.objects.select_for_update().filter(
            id=request_id,
            user=request.user
        ).first()

        if not auth_req:
            return JsonResponse({'status': 'error', 'message': 'Authorization request not found.'}, status=404)

        if auth_req.status != 'PENDING' or auth_req.is_expired():
            if auth_req.status == 'PENDING':
                auth_req.status = 'EXPIRED'
                auth_req.resolved_at = timezone.now()
                auth_req.save(update_fields=['status', 'resolved_at'])
            return JsonResponse({
                'status': 'error',
                'message': 'This authorization request has already expired or been resolved.'
            }, status=400)

        now = timezone.now()

        if decision == 'approve':
            auth_req.status = 'APPROVED'
            auth_req.resolved_at = now
            auth_req.resolved_by_session_key = request.session.session_key
            auth_req.save(update_fields=['status', 'resolved_at', 'resolved_by_session_key'])

            # Automatically cancel any other lingering pending requests for this user
            DeviceAuthorizationRequest.objects.filter(
                user=request.user,
                status='PENDING'
            ).exclude(id=auth_req.id).update(status='EXPIRED', resolved_at=now)

            AuditLog.objects.create(
                actor=request.user,
                actor_username=request.user.username,
                action='DEVICE_AUTHORIZATION_APPROVED',
                ip_address=ip,
                device_id=active_session.device_id or '',
                status='APPROVED',
                details=f"Device authorization approved by active session. Transferring authority to Device B (IP {auth_req.requesting_ip})."
            )
            AuditLog.objects.create(
                actor=request.user,
                actor_username=request.user.username,
                action='DEVICE_AUTH_APPROVED',
                ip_address=ip,
                device_id=active_session.device_id or '',
                status='APPROVED',
                details=f"Device authorization approved by active session. Transferring authority to Device B (IP {auth_req.requesting_ip})."
            )
            SecurityLog.objects.create(
                username_attempted=request.user.username,
                ip_address=ip,
                is_success=True,
                action='DEVICE_AUTH_APPROVED'
            )

            # Send email notification for approval
            notify_device_auth_approved(
                user=request.user,
                requesting_ip=auth_req.requesting_ip,
                approver_ip=ip
            )

            # Log out Device A immediately
            logout(request)

            return JsonResponse({
                'status': 'ok',
                'decision': 'approved',
                'logged_out': True,
                'redirect_url': '/login/'
            })

        else:  # decision == 'deny'
            auth_req.status = 'DENIED'
            auth_req.resolved_at = now
            auth_req.resolved_by_session_key = request.session.session_key
            auth_req.save(update_fields=['status', 'resolved_at', 'resolved_by_session_key'])

            AuditLog.objects.create(
                actor=request.user,
                actor_username=request.user.username,
                action='DEVICE_AUTHORIZATION_DENIED',
                ip_address=ip,
                device_id=active_session.device_id or '',
                status='DENIED',
                details=f"Device authorization denied by active session for login attempt from IP {auth_req.requesting_ip}."
            )
            AuditLog.objects.create(
                actor=request.user,
                actor_username=request.user.username,
                action='DEVICE_AUTH_DENIED',
                ip_address=ip,
                device_id=active_session.device_id or '',
                status='DENIED',
                details=f"Device authorization denied by active session for login attempt from IP {auth_req.requesting_ip}."
            )
            SecurityLog.objects.create(
                username_attempted=request.user.username,
                ip_address=ip,
                is_success=False,
                action='DEVICE_AUTH_DENIED'
            )

            # Send email notification for denial
            notify_device_auth_denied(
                user=request.user,
                requesting_ip=auth_req.requesting_ip,
                denier_ip=ip
            )

            return JsonResponse({
                'status': 'ok',
                'decision': 'denied',
                'logged_out': False
            })


def confirm_device_switch(request):
    """
    Device switching is disabled for Student accounts under Phase 2C single-active-session enforcement.
    """
    if request.method != 'POST':
        return redirect('login')

    user_id = request.session.get('pending_switch_user_id') or request.session.get('pending_user_id')
    if user_id:
        user = User.objects.filter(id=user_id).first()
        if user and is_student_session_enforced(user):
            request.session.pop('pending_switch_user_id', None)
            request.session.pop('pending_switch_backend', None)
            request.session.pop('pending_user_id', None)
            request.session.pop('pending_backend', None)
            messages.error(
                request,
                "Device switching is disabled for student accounts. "
                "Please log out from your existing session before logging in again."
            )
            return redirect('login')

    messages.error(request, "No pending login session found. Please log in again.")
    return redirect('login')


def cancel_device_switch(request):
    """
    Cancels device switch request and preserves the existing session on the other device.
    """
    user_id = request.session.get('pending_switch_user_id') or request.session.get('pending_user_id')
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
    request.session.pop('pending_user_id', None)
    request.session.pop('pending_backend', None)
    messages.info(request, "Login cancelled. Your existing session remains active on your other device.")
    return redirect('login')


def user_logout(request):
    """
    Secure POST-only, CSRF-protected logout endpoint.
    GET requests do not mutate authentication or session state.
    Releases ActiveSession only when session_key matches the current session.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    if request.user.is_authenticated:
        ip = get_client_ip(request)
        device_id = get_or_create_device_id(request)
        current_session_key = request.session.session_key

        if current_session_key:
            ActiveSession.objects.filter(
                user=request.user,
                session_key=current_session_key
            ).delete()

        SecurityLog.objects.create(
            username_attempted=request.user.username,
            ip_address=ip,
            is_success=True,
            action='LOGOUT'
        )
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='SESSION_LOGOUT',
            ip_address=ip,
            device_id=device_id,
            status='SUCCESS',
            details="User logged out cleanly and matching session terminated."
        )
        AuditLog.objects.create(
            actor=request.user,
            actor_username=request.user.username,
            action='LOGOUT',
            ip_address=ip,
            device_id=device_id,
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

    # 4-6. Handle POST atomically under row lock so autosaves cannot race finalization
    if request.method == 'POST':
        with transaction.atomic():
            existing_submission = QuizSubmission.objects.filter(
                student=request.user,
                quiz=quiz
            ).first()
            if existing_submission:
                messages.warning(request, f"You have already submitted '{quiz.title}'.")
                return redirect('quiz_result', submission_id=existing_submission.id)

            attempt = QuizAttempt.objects.select_for_update().filter(
                student=request.user,
                quiz=quiz,
            ).first()

            if attempt and attempt.is_completed:
                messages.warning(request, f"You have already submitted '{quiz.title}'.")
                return redirect('student_dashboard')

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

            now = timezone.now()
            remaining_seconds = int((attempt.deadline - now).total_seconds())
            if remaining_seconds <= 0:
                return _finalize_quiz_submission(request, quiz, attempt, is_timeout=True)

            try:
                attempt.save_answers_from_post(request.POST)
            except ValidationError as exc:
                err_msg = exc.messages[0] if getattr(exc, 'messages', None) else "Invalid answer submission."
                messages.error(request, err_msg)
                request.session.pop(rendered_key, None)
                return redirect('take_quiz', quiz_id=quiz.id)

            action = request.POST.get('action', 'submit_all')
            if action == 'submit_all' or action == 'submit':
                return _finalize_quiz_submission(request, quiz, attempt, is_timeout=False)

            return redirect('take_quiz', quiz_id=quiz.id)

    # 4. GET request: Fetch or create active attempt
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


@student_required
def save_quiz_progress(request, quiz_id):
    """
    CSRF-protected endpoint for saving in-progress quiz answers upon meaningful
    student input so answers are safely persisted before final submission.
    """
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    session_pin_key = f'pin_verified_quiz_{quiz_id}'
    legacy_pin_key = f'verified_quiz_{quiz_id}_user_{request.user.id}'
    if not request.session.get(session_pin_key) and not request.session.get(legacy_pin_key):
        return JsonResponse({'status': 'error', 'message': 'PIN verification required.'}, status=403)

    now = timezone.now()
    with transaction.atomic():
        quiz = get_object_or_404(Quiz, id=quiz_id)

        if not quiz.is_active:
            return JsonResponse({
                'status': 'error',
                'message': 'This quiz is currently inactive and no longer accepting answers.',
            }, status=403)

        if quiz.deadline and now > quiz.deadline:
            return JsonResponse({'status': 'error', 'message': 'Quiz deadline has passed.'}, status=400)

        attempt = QuizAttempt.objects.select_for_update().filter(
            student=request.user,
            quiz=quiz,
        ).first()
        if not attempt:
            return JsonResponse({'status': 'error', 'message': 'No active quiz attempt found.'}, status=404)

        if attempt.is_completed or QuizSubmission.objects.filter(student=request.user, quiz=quiz).exists():
            return JsonResponse({
                'status': 'error',
                'message': 'This quiz has already been submitted.',
            }, status=409)

        if attempt.deadline and now > attempt.deadline:
            return JsonResponse({'status': 'error', 'message': 'Attempt timer has expired.'}, status=400)

        try:
            attempt.save_answers_from_post(request.POST)
        except ValidationError as exc:
            err_msg = exc.messages[0] if getattr(exc, 'messages', None) else 'Invalid answer submission.'
            return JsonResponse({'status': 'error', 'message': err_msg}, status=400)

        saved_count = len(attempt.saved_answers or {})

    return JsonResponse({
        'status': 'saved',
        'saved_count': saved_count,
    })


def _finalize_quiz_submission(request, quiz, attempt, is_timeout=False):
    """
    Helper to atomically lock the QuizAttempt, grade the latest persisted answers,
    record submission with DSA v2 signature, update attempt status, send notifications,
    and record audit log.
    """
    ip = get_client_ip(request)

    with transaction.atomic():
        locked_attempt = QuizAttempt.objects.select_for_update().get(pk=attempt.pk)

        existing_submission = QuizSubmission.objects.filter(
            student=request.user,
            quiz=quiz
        ).first()
        if existing_submission:
            if not locked_attempt.is_completed:
                locked_attempt.is_completed = True
                locked_attempt.save(update_fields=['is_completed'])
            return redirect('quiz_result', submission_id=existing_submission.id)

        if locked_attempt.is_completed:
            return redirect('student_dashboard')

        questions = quiz.questions.all()
        total_questions = questions.count()
        correct_count = 0
        saved_answers = dict(locked_attempt.saved_answers or {})

        for q in questions:
            ans = str(saved_answers.get(str(q.id), "")).strip()
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

        locked_attempt.is_completed = True
        locked_attempt.save(update_fields=['is_completed'])

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
    has_sig = bool(submission.dsa_signature and submission.dsa_signature.strip())

    if not has_sig:
        is_dsa_valid = False
        dsa_status = 'UNSIGNED'
    else:
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
        dsa_status = 'VERIFIED' if is_dsa_valid else 'TAMPERED'

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

    is_admin = request.user.groups.filter(name='Administrator').exists() or request.user.is_superuser

    return render(request, 'quiz/instructor_dashboard.html', {
        'quizzes': quizzes,
        'is_administrator': is_admin,
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
        has_sig = bool(sub.dsa_signature and sub.dsa_signature.strip())
        if not has_sig:
            is_valid = False
            dsa_status = 'UNSIGNED'
        else:
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
            dsa_status = 'VERIFIED' if is_valid else 'TAMPERED'

        submissions_with_status.append({
            'submission': sub,
            'is_dsa_valid': is_valid,
            'dsa_status': dsa_status,
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
        has_sig = bool(sub.dsa_signature and sub.dsa_signature.strip())
        if not has_sig:
            sig_status_str = "UNSIGNED / UNVERIFIED"
        else:
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
            sig_status_str = "VERIFIED" if is_valid else "TAMPERED / INVALID"

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
            sig_status_str
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
    has_sig = bool(submission.dsa_signature and submission.dsa_signature.strip())
    if not has_sig:
        is_dsa_valid = False
        dsa_status = 'UNSIGNED'
    else:
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
        dsa_status = 'VERIFIED' if is_dsa_valid else 'TAMPERED'

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
        'dsa_status': dsa_status,
    })


@admin_required
def security_logs(request):
    """
    Displays the centralized system audit trail and login monitoring events.
    Restricted strictly to system Administrators.
    Ordinary instructors and students are denied access with HTTP 403.
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
