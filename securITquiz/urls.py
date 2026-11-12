"""
URL configuration for securITquiz project.
"""

from django.contrib import admin
from django.urls import path
from quiz import views


urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),

    # Home
    path('', views.home, name='home'),

    # Shared Authentication & Mutual Two-Device Authorization
    path('register/', views.register, name='register'),
    path('register/instructor/', views.register_instructor, name='register_instructor'),
    path('login/', views.user_login, name='login'),
    path('login/waiting-approval/', views.waiting_for_approval, name='waiting_for_approval'),
    path('login/check-approval-status/', views.check_approval_status, name='check_approval_status'),
    path('login/cancel-authorization/', views.cancel_authorization_request, name='cancel_authorization_request'),
    path('login/confirm-device-switch/', views.confirm_device_switch, name='confirm_device_switch'),
    path('login/cancel-device-switch/', views.cancel_device_switch, name='cancel_device_switch'),
    path('auth/pending-device-request/', views.pending_device_request, name='pending_device_request'),
    path('auth/respond-device-request/', views.respond_device_request, name='respond_device_request'),
    path('logout/', views.user_logout, name='logout'),

    # Student Workflow
    path('student/', views.student_dashboard, name='student_dashboard'),
    path('student/profile/', views.student_profile, name='student_profile'),
    path('student/quiz/<int:quiz_id>/verify-pin/', views.verify_quiz_pin, name='verify_quiz_pin'),
    path('student/quiz/<int:quiz_id>/take/', views.take_quiz, name='take_quiz'),
    path('student/quiz/<int:quiz_id>/autosave/', views.save_quiz_progress, name='save_quiz_progress'),
    path('student/quiz/result/<int:submission_id>/', views.quiz_result, name='quiz_result'),

    # Instructor Workflow & Quiz Management
    path('instructor/', views.instructor_dashboard, name='instructor_dashboard'),
    path('instructor/quiz/create/', views.create_quiz, name='create_quiz'),
    path('instructor/quiz/<int:quiz_id>/edit/', views.edit_quiz, name='edit_quiz'),
    path('instructor/quiz/<int:quiz_id>/toggle-status/', views.toggle_quiz_status, name='toggle_quiz_status'),
    path('instructor/quiz/<int:quiz_id>/toggle-results/', views.toggle_quiz_results, name='toggle_quiz_results'),
    path('instructor/quiz/<int:quiz_id>/results/', views.instructor_quiz_results, name='instructor_quiz_results'),
    path('instructor/quiz/<int:quiz_id>/export/', views.export_quiz_results, name='export_quiz_results'),
    path('instructor/quiz/submission/<int:submission_id>/', views.instructor_submission_detail, name='instructor_submission_detail'),

    # Security & Audit Trail Monitoring
    path('instructor/security-logs/', views.security_logs, name='security_logs'),
]
