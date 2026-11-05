
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout

from .models import Quiz, QuizSubmission
from .forms import StudentRegistrationForm, EmailOrUsernameAuthenticationForm
from .decorators import student_required, instructor_required


def home(request):
    return render(request, 'quiz/index.html')


def register(request):
    if request.user.is_authenticated:
        if request.user.groups.filter(name='Instructor').exists():
            return redirect('instructor_dashboard')
        return redirect('student_dashboard')

    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST)

        if form.is_valid():
            form.save()

            messages.success(
                request,
                'Your student account has been created successfully! '
                'You can now log in.'
            )

            return redirect('login')

    else:
        form = StudentRegistrationForm()

    return render(request, 'quiz/register.html', {
        'form': form
    })


def user_login(request):
    if request.user.is_authenticated:
        if request.user.groups.filter(name='Instructor').exists():
            return redirect('instructor_dashboard')
        return redirect('student_dashboard')

    if request.method == 'POST':
        form = EmailOrUsernameAuthenticationForm(
            request,
            data=request.POST
        )

        if form.is_valid():
            user = form.get_user()

            is_student = user.groups.filter(name='Student').exists()
            is_instructor = user.groups.filter(name='Instructor').exists()

            if is_student or is_instructor:
                login(request, user)

                if is_instructor:
                    return redirect('instructor_dashboard')

                return redirect('student_dashboard')

            messages.error(
                request,
                'Your account does not have a valid securITquiz role.'
            )

        else:
            messages.error(
                request,
                'Invalid username/email or password.'
            )

    else:
        form = EmailOrUsernameAuthenticationForm()

    return render(request, 'quiz/login.html', {
        'form': form
    })


def user_logout(request):
    logout(request)

    messages.success(
        request,
        'You have successfully logged out.'
    )

    return redirect('login')


@student_required
def student_dashboard(request):
    available_quizzes = Quiz.objects.all()

    completed_quizzes = QuizSubmission.objects.filter(
        student=request.user
    )

    return render(request, 'quiz/student_dashboard.html', {
        'available_quizzes': available_quizzes,
        'completed_quizzes': completed_quizzes
    })


@instructor_required
def instructor_dashboard(request):
    quizzes = Quiz.objects.filter(
        created_by=request.user
    )

    return render(request, 'quiz/instructor_dashboard.html', {
        'quizzes': quizzes
    })
