from django.shortcuts import render
from .models import Quiz, QuizSubmission

def home(request):
    return render(request, 'quiz/index.html')

def student_dashboard(request):
    available_quizzes = Quiz.objects.all()
    completed_quizzes = QuizSubmission.objects.all()
    return render(request, 'quiz/student_dashboard.html', {
        'available_quizzes': available_quizzes,
        'completed_quizzes': completed_quizzes
    })

def instructor_dashboard(request):
    quizzes = Quiz.objects.all()
    return render(request, 'quiz/instructor_dashboard.html', {'quizzes': quizzes})