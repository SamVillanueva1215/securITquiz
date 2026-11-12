from functools import wraps
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.http import JsonResponse
from django.shortcuts import render, resolve_url
from django.urls import reverse

from .middleware import get_client_ip, is_ajax_request
from .models import AuditLog


def _deny_with_audit(request, user, required_roles, user_roles, denial_reason=None, extra_context=None):
    """
    Logs an UNAUTHORIZED_ACCESS_ATTEMPT audit entry and renders HTTP 403 Forbidden
    (or JSON 403 for AJAX requests).
    """
    AuditLog.objects.create(
        actor=user,
        actor_username=user.username,
        action='UNAUTHORIZED_ACCESS_ATTEMPT',
        ip_address=get_client_ip(request),
        status='DENIED',
        details=f"Access denied to {request.path}. Required: {', '.join(required_roles)}."
    )
    if is_ajax_request(request):
        return JsonResponse({
            'status': 'error',
            'message': denial_reason or 'Access denied.',
        }, status=403)
    context = {
        'required_roles': required_roles,
        'user_roles': list(user_roles) or ['No assigned role'],
    }
    if denial_reason:
        context['denial_reason'] = denial_reason
    if extra_context:
        context.update(extra_context)
    return render(request, 'quiz/403.html', context, status=403)


def role_required(allowed_roles):
    """
    Decorator that strictly enforces Role-Based Access Control (RBAC).
    Denies access with HTTP 403 Forbidden if the authenticated user
    does not possess the required role, and returns explicit JSON 401 on
    unauthenticated AJAX requests so clients never treat login HTML as JSON.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                if is_ajax_request(request):
                    return JsonResponse({
                        'status': 'session_expired',
                        'preserved': False,
                        'message': (
                            'Your session has expired or you are no longer logged in. '
                            'Latest changes could not be saved automatically. Please log in again.'
                        ),
                        'login_url': reverse('login'),
                    }, status=401)
                return redirect_to_login(request.get_full_path(), resolve_url('login'))

            user = request.user
            user_roles = set(user.groups.values_list('name', flat=True))

            # Check if user has at least one of the allowed roles
            if any(role in user_roles for role in allowed_roles):
                return view_func(request, *args, **kwargs)

            return _deny_with_audit(
                request=request,
                user=user,
                required_roles=allowed_roles,
                user_roles=user_roles,
            )

        return _wrapped_view

    return decorator


# Convenience shortcuts for views
student_required = role_required('Student')


def instructor_required(view_func):
    """
    Decorator that strictly enforces that the user:
    1. Is authenticated.
    2. Possesses the 'Instructor' group membership.
    3. Has an associated InstructorProfile with status == 'APPROVED'.

    Pending and Rejected instructors are strictly denied access with HTTP 403.
    Missing InstructorProfile records are handled safely and denied access with HTTP 403.
    """
    @login_required(login_url='login')
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        user_roles = set(user.groups.values_list('name', flat=True))

        # 1. Group membership check
        if 'Instructor' not in user_roles:
            return _deny_with_audit(
                request=request,
                user=user,
                required_roles=['Instructor (Approved)'],
                user_roles=user_roles,
                denial_reason='Instructor role is required.',
            )

        # 2. Safe profile check
        profile = getattr(user, 'instructor_profile', None)
        if profile is None:
            return _deny_with_audit(
                request=request,
                user=user,
                required_roles=['Instructor (Approved)'],
                user_roles=user_roles,
                denial_reason='Instructor profile not found. Please contact an administrator.',
            )

        # 3. Status approval check
        if not profile.is_authorized():
            status_display = profile.get_status_display()
            reason = f"Your instructor account status is currently {status_display}."
            if profile.status == 'REJECTED' and profile.rejection_reason:
                reason += f" Reason: {profile.rejection_reason}"
            elif profile.status == 'PENDING':
                reason += " Your account must be approved by an administrator before accessing instructor features."
            return _deny_with_audit(
                request=request,
                user=user,
                required_roles=['Instructor (Approved)'],
                user_roles=user_roles,
                denial_reason=reason,
                extra_context={'instructor_status': profile.status},
            )

        return view_func(request, *args, **kwargs)

    return _wrapped_view


def admin_required(view_func):
    """
    Decorator that restricts access strictly to users in the Administrator group
    (or superusers).
    Ordinary instructors and students are denied access with HTTP 403.
    """
    @login_required(login_url='login')
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        user_roles = set(user.groups.values_list('name', flat=True))

        if 'Administrator' in user_roles or user.is_superuser:
            return view_func(request, *args, **kwargs)

        return _deny_with_audit(
            request=request,
            user=user,
            required_roles=['Administrator'],
            user_roles=user_roles,
            denial_reason='Administrator role is required to access system security and audit logs.',
        )

    return _wrapped_view
