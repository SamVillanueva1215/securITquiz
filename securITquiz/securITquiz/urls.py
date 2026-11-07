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

    # Student
    path('student/', views.student_dashboard, name='student_dashboard'),
    path('student/quiz/<int:quiz_id>/verify-pin/', views.verify_quiz_pin, name='verify_quiz_pin'),
    path('student/quiz/<int:quiz_id>/take/', views.take_quiz, name='take_quiz'),
    path('student/quiz/result/<int:submission_id>/', views.quiz_result, name='quiz_result'),
    path('register/', views.register, name='register'),

    # Shared Login and Logout
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    # Instructor
    path('instructor/', views.instructor_dashboard, name='instructor_dashboard'),
    path('instructor/quiz/create/', views.create_quiz, name='create_quiz'),
    path('instructor/quiz/<int:quiz_id>/edit/', views.edit_quiz, name='edit_quiz'),
    path('instructor/quiz/<int:quiz_id>/results/', views.instructor_quiz_results, name='instructor_quiz_results'),
    path('instructor/quiz/submission/<int:submission_id>/', views.instructor_submission_detail, name='instructor_submission_detail'),
]
