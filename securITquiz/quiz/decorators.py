from functools import wraps
from django.contrib.auth.decorators import login_required
from django.shortcuts import render


def role_required(allowed_roles):
    """
    Decorator that strictly enforces Role-Based Access Control (RBAC).
    Denies access with HTTP 403 Forbidden if the authenticated user
    does not possess the required role.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(view_func):
        @login_required(login_url='login')
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user = request.user
            user_roles = set(user.groups.values_list('name', flat=True))

            # Check if user has at least one of the allowed roles
            if any(role in user_roles for role in allowed_roles):
                return view_func(request, *args, **kwargs)

            # Access Denied: strictly enforce role protection (HTTP 403)
            return render(
                request,
                'quiz/403.html',
                {
                    'required_roles': allowed_roles,
                    'user_roles': list(user_roles) or ['No assigned role'],
                },
                status=403
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
            return render(
                request,
                'quiz/403.html',
                {
                    'required_roles': ['Instructor (Approved)'],
                    'user_roles': list(user_roles) or ['No assigned role'],
                    'denial_reason': 'Instructor role is required.',
                },
                status=403
            )

        # 2. Safe profile check
        profile = getattr(user, 'instructor_profile', None)
        if profile is None:
            return render(
                request,
                'quiz/403.html',
                {
                    'required_roles': ['Instructor (Approved)'],
                    'user_roles': list(user_roles),
                    'denial_reason': 'Instructor profile not found. Please contact an administrator.',
                },
                status=403
            )

        # 3. Status approval check
        if not profile.is_authorized():
            status_display = profile.get_status_display()
            reason = f"Your instructor account status is currently {status_display}."
            if profile.status == 'REJECTED' and profile.rejection_reason:
                reason += f" Reason: {profile.rejection_reason}"
            elif profile.status == 'PENDING':
                reason += " Your account must be approved by an administrator before accessing instructor features."
            return render(
                request,
                'quiz/403.html',
                {
                    'required_roles': ['Instructor (Approved)'],
                    'user_roles': list(user_roles),
                    'instructor_status': profile.status,
                    'denial_reason': reason,
                },
                status=403
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

        return render(
            request,
            'quiz/403.html',
            {
                'required_roles': ['Administrator'],
                'user_roles': list(user_roles) or ['No assigned role'],
                'denial_reason': 'Administrator role is required to access system security and audit logs.',
            },
            status=403
        )

    return _wrapped_view
