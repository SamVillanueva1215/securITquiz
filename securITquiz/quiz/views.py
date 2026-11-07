import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout
from django.db import transaction
from django.utils import timezone

from .models import Quiz, QuizSubmission, Question
from .forms import (
    StudentRegistrationForm,
    EmailOrUsernameAuthenticationForm,
    QuizForm,
    validate_questions_data,
    generate_secure_pin
)
from .decorators import student_required, instructor_required
from .crypto import generate_dsa_signature, verify_dsa_signature


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
    available_quizzes = Quiz.objects.all().order_by('-created_at')

    completed_submissions = QuizSubmission.objects.filter(
        student=request.user
    ).select_related('quiz')

    completed_quiz_ids = set(completed_submissions.values_list('quiz_id', flat=True))

    return render(request, 'quiz/student_dashboard.html', {
        'available_quizzes': available_quizzes,
        'completed_quizzes': completed_submissions,
        'completed_quiz_ids': completed_quiz_ids,
        'now': timezone.now()
    })


@student_required
def take_quiz(request, quiz_id):
    """
    Renders the student quiz-taking interface, validates submitted answers,
    computes scores, and generates a cryptographic DSA signature for grade integrity.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)

    # 1. Verify deadline
    if quiz.deadline and timezone.now() > quiz.deadline:
        messages.error(
            request,
            f"The deadline for '{quiz.title}' has passed. Submissions are no longer accepted."
        )
        return redirect('student_dashboard')

    # 2. Prevent duplicate submissions
    existing_submission = QuizSubmission.objects.filter(
        student=request.user,
        quiz=quiz
    ).first()
    if existing_submission:
        messages.warning(
            request,
            f"You have already submitted '{quiz.title}'. You cannot retake this quiz."
        )
        return redirect('quiz_result', submission_id=existing_submission.id)

    # 3. Verify quiz has questions
    questions = quiz.questions.all().order_by('id')
    if not questions.exists():
        messages.error(
            request,
            f"The quiz '{quiz.title}' does not have any questions available."
        )
        return redirect('student_dashboard')

    # 4. Handle quiz submission and automated grading
    if request.method == 'POST':
        # Re-check deadline at submission time to prevent late submits
        if quiz.deadline and timezone.now() > quiz.deadline:
            messages.error(
                request,
                f"Your submission for '{quiz.title}' was rejected because the deadline has passed."
            )
            return redirect('student_dashboard')

        # Re-check duplicate submission to prevent race conditions
        if QuizSubmission.objects.filter(student=request.user, quiz=quiz).exists():
            messages.warning(request, "A submission for this quiz was already recorded.")
            return redirect('student_dashboard')

        # Server-side grading (never trust client scores)
        total_questions = questions.count()
        correct_count = 0

        for question in questions:
            field_name = f"question_{question.id}"
            student_answer = request.POST.get(field_name, "").strip()

            # Compare answers case-insensitively
            if student_answer and student_answer.upper() == question.correct_answer.strip().upper():
                correct_count += 1

        score = float(correct_count)
        percentage = round((score / total_questions) * 100.0, 2)

        # Save submission and generate cryptographic DSA signature atomically
        with transaction.atomic():
            submission = QuizSubmission(
                student=request.user,
                quiz=quiz,
                score=score,
                percentage=percentage,
                dsa_signature=""
            )
            submission.save()

            timestamp_str = submission.submitted_at.isoformat()
            submission.dsa_signature = generate_dsa_signature(
                student_username=request.user.username,
                quiz_id=quiz.id,
                score=score,
                percentage=percentage,
                timestamp_str=timestamp_str
            )
            submission.save(update_fields=['dsa_signature'])

        messages.success(
            request,
            f"Quiz '{quiz.title}' submitted successfully! You scored {int(score)}/{total_questions} ({percentage}%)."
        )
        return redirect('quiz_result', submission_id=submission.id)

    # 5. GET request: render the quiz-taking form
    return render(request, 'quiz/take_quiz.html', {
        'quiz': quiz,
        'questions': questions,
        'total_questions': questions.count(),
    })


@student_required
def quiz_result(request, submission_id):
    """
    Displays the completed quiz results, score breakdown, and cryptographic
    DSA signature verification.
    """
    submission = get_object_or_404(
        QuizSubmission.objects.select_related('quiz', 'student'),
        id=submission_id
    )

    # Only allow the student who took the quiz to view their results
    if submission.student != request.user:
        messages.error(
            request,
            "Access Denied: You cannot view another student's quiz results."
        )
        return redirect('student_dashboard')

    # Verify cryptographic DSA signature
    timestamp_str = submission.submitted_at.isoformat()
    is_dsa_valid = verify_dsa_signature(
        student_username=submission.student.username,
        quiz_id=submission.quiz.id,
        score=submission.score,
        percentage=submission.percentage,
        timestamp_str=timestamp_str,
        hex_signature=submission.dsa_signature
    )

    total_questions = submission.quiz.questions.count()

    return render(request, 'quiz/quiz_result.html', {
        'submission': submission,
        'quiz': submission.quiz,
        'total_questions': total_questions,
        'is_dsa_valid': is_dsa_valid,
    })


@instructor_required
def instructor_dashboard(request):
    quizzes = Quiz.objects.filter(
        created_by=request.user
    )

    return render(request, 'quiz/instructor_dashboard.html', {
        'quizzes': quizzes
    })


@instructor_required
def instructor_quiz_results(request, quiz_id):
    """
    Displays the quiz results and student submissions for a quiz created by the instructor.
    Enforces ownership: instructors may only view results for quizzes they created.
    """
    quiz = get_object_or_404(Quiz, id=quiz_id)

    # Enforce quiz ownership: only the creator can view results
    if quiz.created_by != request.user:
        return render(
            request,
            'quiz/403.html',
            {
                'required_roles': ['Quiz Owner (Instructor)'],
                'user_roles': ['Instructor (Not Quiz Owner)'],
            },
            status=403
        )

    submissions = QuizSubmission.objects.filter(
        quiz=quiz
    ).select_related('student', 'student__student_profile').order_by('-submitted_at')

    # Verify DSA digital signature for each submission
    submissions_with_status = []
    for sub in submissions:
        timestamp_str = sub.submitted_at.isoformat()
        is_valid = verify_dsa_signature(
            student_username=sub.student.username,
            quiz_id=quiz.id,
            score=sub.score,
            percentage=sub.percentage,
            timestamp_str=timestamp_str,
            hex_signature=sub.dsa_signature
        )
        submissions_with_status.append({
            'submission': sub,
            'is_dsa_valid': is_valid,
        })

    total_submissions = len(submissions_with_status)
    total_questions = quiz.questions.count()

    if total_submissions > 0:
        percentages = [s['submission'].percentage for s in submissions_with_status]
        avg_percentage = round(sum(percentages) / total_submissions, 1)
        pass_count = sum(1 for p in percentages if p >= 50.0)
        pass_rate = round((pass_count / total_submissions) * 100.0, 1)
        highest_score = max(percentages)
        lowest_score = min(percentages)
    else:
        avg_percentage = None
        pass_rate = None
        highest_score = None
        lowest_score = None

    return render(request, 'quiz/instructor_quiz_results.html', {
        'quiz': quiz,
        'submissions_with_status': submissions_with_status,
        'total_submissions': total_submissions,
        'total_questions': total_questions,
        'avg_percentage': avg_percentage,
        'pass_rate': pass_rate,
        'highest_score': highest_score,
        'lowest_score': lowest_score,
    })


@instructor_required
def instructor_submission_detail(request, submission_id):
    """
    Allows an instructor to inspect an individual student's submission result,
    grading details, questions with answer key, and cryptographic DSA verification.
    Enforces ownership: instructors may only view submissions for quizzes they created.
    """
    submission = get_object_or_404(
        QuizSubmission.objects.select_related('quiz', 'student', 'student__student_profile'),
        id=submission_id
    )

    # Enforce quiz ownership: only the creator of the quiz can view individual submission
    if submission.quiz.created_by != request.user:
        return render(
            request,
            'quiz/403.html',
            {
                'required_roles': ['Quiz Owner (Instructor)'],
                'user_roles': ['Instructor (Not Quiz Owner)'],
            },
            status=403
        )

    # Verify cryptographic DSA signature
    timestamp_str = submission.submitted_at.isoformat()
    is_dsa_valid = verify_dsa_signature(
        student_username=submission.student.username,
        quiz_id=submission.quiz.id,
        score=submission.score,
        percentage=submission.percentage,
        timestamp_str=timestamp_str,
        hex_signature=submission.dsa_signature
    )

    questions = submission.quiz.questions.all().order_by('id')
    total_questions = questions.count()

    return render(request, 'quiz/instructor_submission_detail.html', {
        'submission': submission,
        'quiz': submission.quiz,
        'student': submission.student,
        'questions': questions,
        'total_questions': total_questions,
        'is_dsa_valid': is_dsa_valid,
    })


def _parse_indexed_questions(post_data):
    """
    Parses questions from POST form data where keys are formatted like:
    question_text_0, question_type_0, option_a_0, ...
    """
    questions = []
    indices = set()
    for key in post_data.keys():
        if key.startswith('question_text_'):
            parts = key.split('_')
            if len(parts) >= 3 and parts[-1].isdigit():
                indices.add(int(parts[-1]))

    for idx in sorted(indices):
        questions.append({
            'question_text': post_data.get(f'question_text_{idx}', ''),
            'question_type': post_data.get(f'question_type_{idx}', 'MCQ'),
            'option_a': post_data.get(f'option_a_{idx}', ''),
            'option_b': post_data.get(f'option_b_{idx}', ''),
            'option_c': post_data.get(f'option_c_{idx}', ''),
            'option_d': post_data.get(f'option_d_{idx}', ''),
            'correct_answer': post_data.get(f'correct_answer_{idx}', '')
        })

    return questions


@instructor_required
def create_quiz(request):
    """
    Allows instructors to create a quiz with its questions.
    Requirements:
    1. Guarded by @instructor_required (HTTP 403 for non-instructors).
    2. At least one question is required.
    3. Server-side validation of all questions and choices.
    4. Atomic transaction saving Quiz and all Questions together.
    """
    if request.method == 'POST':
        form = QuizForm(request.POST)

        # Parse submitted questions from JSON payload or indexed POST fields
        questions_json = request.POST.get('questions_data')
        raw_questions = []
        if questions_json:
            try:
                raw_questions = json.loads(questions_json)
            except (json.JSONDecodeError, TypeError):
                messages.error(request, "Invalid questions format submitted.")
        else:
            raw_questions = _parse_indexed_questions(request.POST)

        # Validate all questions on the server side
        validated_questions, question_errors = validate_questions_data(raw_questions)

        # Validate quiz metadata and question payload together
        if form.is_valid() and not question_errors:
            try:
                with transaction.atomic():
                    quiz = form.save(commit=False)
                    quiz.created_by = request.user
                    quiz.save()

                    for q_data in validated_questions:
                        Question.objects.create(
                            quiz=quiz,
                            question_text=q_data['question_text'],
                            question_type=q_data['question_type'],
                            option_a=q_data.get('option_a'),
                            option_b=q_data.get('option_b'),
                            option_c=q_data.get('option_c'),
                            option_d=q_data.get('option_d'),
                            correct_answer=q_data['correct_answer']
                        )

                messages.success(
                    request,
                    f"Quiz '{quiz.title}' with {len(validated_questions)} question(s) was created successfully!"
                )
                return redirect('instructor_dashboard')

            except Exception as e:
                messages.error(
                    request,
                    f"An error occurred while saving the quiz: {str(e)}. All changes have been rolled back."
                )
        else:
            for err in question_errors:
                messages.error(request, err)

    else:
        initial_pin = generate_secure_pin()
        form = QuizForm(initial={'access_pin': initial_pin, 'time_limit_minutes': 15})
        raw_questions = []

    return render(request, 'quiz/create_quiz.html', {
        'form': form,
        'existing_questions_json': json.dumps(raw_questions) if raw_questions else '[]'
    })
