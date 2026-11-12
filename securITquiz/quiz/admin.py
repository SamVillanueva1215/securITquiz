
from django.contrib import admin
from .models import (
    StudentProfile,
    InstructorProfile,
    Quiz,
    Question,
    QuizSubmission,
    SecurityLog,
    AuditLog
)


@admin.register(StudentProfile)
class StudentProfileAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'student_id', 'user')
    search_fields = ('full_name', 'student_id', 'user__username')


@admin.register(InstructorProfile)
class InstructorProfileAdmin(admin.ModelAdmin):
    list_display = (
        'full_name',
        'user',
        'department',
        'status',
        'requested_at',
        'reviewed_at',
        'reviewed_by',
    )
    list_filter = ('status', 'department', 'requested_at')
    search_fields = ('full_name', 'user__username', 'user__email', 'department')
    readonly_fields = ('requested_at', 'reviewed_at', 'reviewed_by')
    actions = ['approve_instructors', 'reject_instructors']

    @admin.action(description="Approve selected instructor applications")
    def approve_instructors(self, request, queryset):
        count = 0
        for profile in queryset:
            profile.approve(request.user)
            count += 1
        self.message_user(
            request,
            f"{count} instructor application(s) have been successfully approved."
        )

    @admin.action(description="Reject selected instructor applications")
    def reject_instructors(self, request, queryset):
        count = 0
        for profile in queryset:
            profile.reject(request.user, reason="Application rejected by administrator via Admin Console.")
            count += 1
        self.message_user(
            request,
            f"{count} instructor application(s) have been rejected."
        )


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


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'actor_username', 'action', 'status', 'ip_address', 'device_id')
    list_filter = ('action', 'status', 'timestamp')
    search_fields = ('actor_username', 'details', 'ip_address', 'device_id')
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
