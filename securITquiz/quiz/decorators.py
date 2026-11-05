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
instructor_required = role_required('Instructor')
