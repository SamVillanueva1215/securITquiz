
from django.contrib import admin
from .models import StudentProfile, Quiz, Question, QuizSubmission, SecurityLog


@admin.register(StudentProfile)
class StudentProfileAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'student_id', 'user')
    search_fields = ('full_name', 'student_id', 'user__username')


@admin.register(Quiz)
class QuizAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_by', 'deadline', 'created_at')
    search_fields = ('title', 'created_by__username')


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('quiz', 'question_type', 'question_text')
    list_filter = ('question_type', 'quiz')


@admin.register(QuizSubmission)
class QuizSubmissionAdmin(admin.ModelAdmin):
    list_display = ('student', 'quiz', 'score', 'percentage', 'submitted_at')
    search_fields = ('student__username', 'quiz__title')


@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('username_attempted', 'ip_address', 'timestamp', 'is_success')
    list_filter = ('is_success',)
    search_fields = ('username_attempted', 'ip_address')
