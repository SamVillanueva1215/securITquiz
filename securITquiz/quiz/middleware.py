
"""
securITquiz - Single Active Session & Security Middleware
Enforces single active session and 5-minute inactivity timeout.
"""

import uuid
import datetime
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import logout as auth_logout
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.sessions.models import Session
from .models import ActiveSession, AuditLog, SecurityLog


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


def cleanup_expired_sessions(user=None, ip_address='127.0.0.1'):
    """
    Cleans up stale or expired ActiveSession records and logs SESSION_EXPIRED audit events.
    Can be called for a specific user (e.g. during login) or globally.
    """
    now = timezone.now()
    threshold = now - datetime.timedelta(minutes=5)
    qs = ActiveSession.objects.filter(last_activity__lt=threshold)
    if user:
        qs = qs.filter(user=user)

    for active in qs:
        AuditLog.objects.create(
            actor=active.user,
            actor_username=active.user.username,
            action='SESSION_EXPIRED',
            ip_address=ip_address,
            status='EXPIRED',
            details="Session automatically expired after 5 minutes of inactivity."
        )
        SecurityLog.objects.create(
            username_attempted=active.user.username,
            ip_address=ip_address,
            is_success=False,
            action='SESSION_EXPIRED'
        )
        Session.objects.filter(session_key=active.session_key).delete()
        active.delete()


class SingleActiveSessionMiddleware:
    """
    Middleware that ensures an authenticated user account has exactly one active session.
    1. If the user logs in on a new device and is approved, the old device session is terminated.
    2. Enforces a strict 5-minute inactivity expiration window.
    3. Refreshes the inactivity timestamp on legitimate authenticated requests.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        device_id = get_or_create_device_id(request)
        request.device_id = device_id
        if hasattr(request, 'session') and request.session.get('device_id') != device_id:
            request.session['device_id'] = device_id

        if request.user.is_authenticated:
            session_key = request.session.session_key
            if not session_key:
                request.session.save()
                session_key = request.session.session_key

            active_session = ActiveSession.objects.filter(user=request.user).first()
            now = timezone.now()

            if active_session:
                # 1. Detect if another device took over the session
                if active_session.session_key != session_key:
                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='SESSION_REVOKED',
                        ip_address=get_client_ip(request),
                        device_id=device_id,
                        status='REVOKED',
                        details="Session terminated because another authorized device assumed active account authority."
                    )
                    SecurityLog.objects.create(
                        username_attempted=request.user.username,
                        ip_address=get_client_ip(request),
                        is_success=False,
                        action='SESSION_REVOKED'
                    )
                    auth_logout(request)
                    messages.warning(
                        request,
                        "Your session was terminated because this account was logged into from another device."
                    )
                    return redirect('login')

                # 2. Check 5-minute inactivity timeout
                if active_session.is_expired(timeout_minutes=5):
                    AuditLog.objects.create(
                        actor=request.user,
                        actor_username=request.user.username,
                        action='SESSION_EXPIRED',
                        ip_address=get_client_ip(request),
                        device_id=device_id,
                        status='EXPIRED',
                        details="Session automatically expired after 5 minutes of inactivity."
                    )
                    SecurityLog.objects.create(
                        username_attempted=request.user.username,
                        ip_address=get_client_ip(request),
                        is_success=False,
                        action='SESSION_EXPIRED'
                    )
                    Session.objects.filter(session_key=active_session.session_key).delete()
                    active_session.delete()
                    auth_logout(request)
                    messages.info(
                        request,
                        "Your session has expired due to 5 minutes of inactivity. Please log in again."
                    )
                    return redirect('login')

                # 3. Legitimate activity: refresh inactivity timestamp (throttled to every 30s)
                if (now - active_session.last_activity).total_seconds() > 30:
                    active_session.last_activity = now
                    if active_session.device_id != device_id:
                        active_session.device_id = device_id
                        active_session.save(update_fields=['last_activity', 'device_id'])
                    else:
                        active_session.save(update_fields=['last_activity'])

            else:
                # Initial active session creation if missing
                ActiveSession.objects.create(
                    user=request.user,
                    session_key=session_key,
                    device_id=device_id,
                    ip_address=get_client_ip(request),
                    last_activity=now
                )

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
