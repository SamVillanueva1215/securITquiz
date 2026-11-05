
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
    path('register/', views.register, name='register'),

    # Shared Login and Logout
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    # Instructor
    path('instructor/', views.instructor_dashboard, name='instructor_dashboard'),
]
