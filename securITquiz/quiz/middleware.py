
"""
securITquiz - Single Active Session & Security Middleware
Enforces single active session and 5-minute inactivity timeout.
"""

import datetime
from django.utils import timezone
from django.contrib.auth import logout as auth_logout
from django.contrib import messages
from django.shortcuts import redirect
from .models import ActiveSession, AuditLog


def get_client_ip(request):
    """Retrieves client IP address reliably from HTTP headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


class SingleActiveSessionMiddleware:
    """
    Middleware that ensures an authenticated user account has exactly one active session.
    1. If the user logs in on a new device and confirms switching, the old device session is terminated.
    2. Enforces a strict 5-minute inactivity expiration window.
    3. Refreshes the inactivity timestamp on legitimate authenticated requests.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
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
                        status='EXPIRED',
                        details="Session automatically expired after 5 minutes of inactivity."
                    )
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
                    active_session.save(update_fields=['last_activity'])

            else:
                # Initial active session creation if missing
                ActiveSession.objects.create(
                    user=request.user,
                    session_key=session_key,
                    ip_address=get_client_ip(request),
                    last_activity=now
                )

        response = self.get_response(request)
        return response
