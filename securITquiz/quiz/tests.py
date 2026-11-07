import json
from datetime import timedelta
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.urls import reverse

from quiz.models import StudentProfile, Quiz, Question, QuizSubmission
from quiz.forms import QuizForm, validate_questions_data, generate_secure_pin


class RoleBasedAccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Ensure groups exist
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        # Create a test instructor
        self.instructor = User.objects.create_user(
            username='instructor_bob',
            email='bob@university.edu',
            password='SecretPassword123!'
        )
        self.instructor.groups.add(self.instructor_group)

        # Create a test student
        self.student = User.objects.create_user(
            username='student_alice',
            email='alice@university.edu',
            password='SecretPassword123!'
        )
        self.student.groups.add(self.student_group)
        StudentProfile.objects.create(
            user=self.student,
            full_name='Alice Student',
            student_id='STU1001'
        )

    def test_passwords_use_argon2(self):
        """Verify that newly created passwords use the Argon2 algorithm."""
        self.assertTrue(self.student.password.startswith('argon2'))
        self.assertTrue(self.instructor.password.startswith('argon2'))

    def test_login_with_username_as_student(self):
        """Student logging in with username redirects to student dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'student_alice',
            'password': 'SecretPassword123!'
        })
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_login_with_email_as_student(self):
        """Student logging in with email redirects to student dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'alice@university.edu',
            'password': 'SecretPassword123!'
        })
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_login_with_username_as_instructor(self):
        """Instructor logging in with username redirects to instructor dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'instructor_bob',
            'password': 'SecretPassword123!'
        })
        self.assertRedirects(response, reverse('instructor_dashboard'))

    def test_login_with_email_as_instructor(self):
        """Instructor logging in with email redirects to instructor dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'bob@university.edu',
            'password': 'SecretPassword123!'
        })
        self.assertRedirects(response, reverse('instructor_dashboard'))

    def test_student_denied_from_instructor_dashboard(self):
        """A student accessing the instructor dashboard is denied with HTTP 403."""
        self.client.login(username='student_alice', password='SecretPassword123!')
        response = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)
        self.assertContains(response, 'Instructor', status_code=403)

    def test_instructor_denied_from_student_dashboard(self):
        """An instructor accessing the student dashboard is denied with HTTP 403."""
        self.client.login(username='instructor_bob', password='SecretPassword123!')
        response = self.client.get(reverse('student_dashboard'))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)
        self.assertContains(response, 'Student', status_code=403)

    def test_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated user accessing protected dashboards is redirected to login."""
        response = self.client.get(reverse('student_dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

        response = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_student_registration_workflow(self):
        """Student registers via registration page, automatically gets Student role & Argon2 password."""
        response = self.client.post(reverse('register'), {
            'full_name': 'Charlie Brown',
            'student_id': 'STU2002',
            'email': 'charlie@university.edu',
            'username': 'student_charlie',
            'password1': 'SecureStudentPass123!',
            'password2': 'SecureStudentPass123!'
        })
        self.assertRedirects(response, reverse('login'))

        charlie = User.objects.get(username='student_charlie')
        self.assertTrue(charlie.password.startswith('argon2'))
        self.assertTrue(charlie.groups.filter(name='Student').exists())
        self.assertFalse(charlie.groups.filter(name='Instructor').exists())
        self.assertEqual(charlie.student_profile.student_id, 'STU2002')


class CreateQuizUnitAndIntegrationTests(TestCase):
    """
    Tests for Instructor Create Quiz functionality:
    - Role restrictions (only Instructors can access)
    - Minimum 1 question requirement
    - MCQ validations (question text, 4 options, single correct answer)
    - True/False validations (question text, True or False correct answer)
    - Cryptographically secure and unique 6-character access PIN
    - Atomic rollback when validation or saving fails
    - Successful quiz and question creation
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

        self.instructor = User(
            username='prof_dumbledore',
            email='albus@hogwarts.edu'
        )
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        self.student = User(
            username='student_potter',
            email='harry@hogwarts.edu'
        )
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)

    def test_unauthenticated_user_redirected_from_create_quiz(self):
        """Unauthenticated user accessing create_quiz is redirected to login."""
        response = self.client.get(reverse('create_quiz'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_student_denied_from_create_quiz(self):
        """Student accessing create_quiz is rejected with HTTP 403."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('create_quiz'))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_instructor_can_access_create_quiz(self):
        """Instructor can access create_quiz and receives a pre-populated secure PIN."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('create_quiz'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create New Quiz')
        self.assertContains(response, 'Generate New PIN')
        # Form has initial 6-character PIN
        initial_pin = response.context['form']['access_pin'].value()
        self.assertEqual(len(initial_pin), 6)
        self.assertTrue(initial_pin.isalnum())

    def test_access_pin_uniqueness(self):
        """Access PIN must be unique across quizzes."""
        # Create an existing quiz
        deadline = timezone.now() + timedelta(days=2)
        Quiz.objects.create(
            title='Existing Quiz',
            description='Test',
            time_limit_minutes=20,
            deadline=deadline,
            access_pin='SEC123',
            created_by=self.instructor
        )

        # Duplicate PIN should be rejected by QuizForm
        form = QuizForm(data={
            'title': 'New Quiz',
            'time_limit_minutes': 15,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'SEC123'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('access_pin', form.errors)
        self.assertIn('already in use', form.errors['access_pin'][0])

        # Unique PIN should pass
        unique_pin = generate_secure_pin()
        self.assertNotEqual(unique_pin, 'SEC123')
        form2 = QuizForm(data={
            'title': 'New Quiz',
            'time_limit_minutes': 15,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': unique_pin
        })
        self.assertTrue(form2.is_valid())

    def test_minimum_one_question_required(self):
        """Submitting a quiz without any questions is rejected on the server side."""
        self.client.force_login(self.instructor)
        deadline = timezone.now() + timedelta(days=3)
        response = self.client.post(reverse('create_quiz'), {
            'title': 'Empty Quiz',
            'description': 'No questions attached',
            'time_limit_minutes': 15,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'NOQ123',
            'questions_data': json.dumps([])
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Quiz.objects.filter(access_pin='NOQ123').count(), 0)

    def test_mcq_question_server_side_validation(self):
        """MCQ questions require text, all 4 options, and one valid correct answer."""
        # Missing Option C and invalid correct answer
        raw = [{
            'question_text': 'What is RSA?',
            'question_type': 'MCQ',
            'option_a': 'Cipher',
            'option_b': 'Protocol',
            'option_c': '',
            'option_d': 'Algorithm',
            'correct_answer': 'Z'
        }]
        validated, errors = validate_questions_data(raw)
        self.assertEqual(len(validated), 0)
        self.assertTrue(any('Option C is required' in e for e in errors))
        self.assertTrue(any('Exactly one correct answer must be selected' in e for e in errors))

    def test_tf_question_server_side_validation(self):
        """TF questions require text and a correct answer of True or False."""
        # Invalid answer 'Maybe'
        raw = [{
            'question_text': 'Is AES symmetric?',
            'question_type': 'TF',
            'correct_answer': 'Maybe'
        }]
        validated, errors = validate_questions_data(raw)
        self.assertEqual(len(validated), 0)
        self.assertTrue(any("must be either 'True' or 'False'" in e for e in errors))

        # Valid answer 'True'
        raw_valid = [{
            'question_text': 'Is AES symmetric?',
            'question_type': 'TF',
            'correct_answer': 'True'
        }]
        validated, errors = validate_questions_data(raw_valid)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(validated), 1)
        self.assertEqual(validated[0]['option_a'], 'True')
        self.assertEqual(validated[0]['option_b'], 'False')
        self.assertEqual(validated[0]['correct_answer'], 'True')

    def test_atomic_transaction_rollback_on_failure(self):
        """If question validation fails, the quiz is not saved to the database."""
        self.client.force_login(self.instructor)
        deadline = timezone.now() + timedelta(days=2)

        # Valid quiz metadata, but invalid question payload
        invalid_questions = [
            {
                'question_text': '',
                'question_type': 'MCQ',
                'option_a': 'A',
                'option_b': 'B',
                'option_c': 'C',
                'option_d': 'D',
                'correct_answer': 'A'
            }
        ]

        response = self.client.post(reverse('create_quiz'), {
            'title': 'Rollback Quiz',
            'description': 'Should not persist',
            'time_limit_minutes': 20,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'ROL001',
            'questions_data': json.dumps(invalid_questions)
        })

        self.assertEqual(response.status_code, 200)
        # Verify complete rollback: neither quiz nor question exists
        self.assertFalse(Quiz.objects.filter(access_pin='ROL001').exists())
        self.assertEqual(Question.objects.count(), 0)

    def test_successful_quiz_creation_with_mcq_and_tf(self):
        """Instructor successfully creates a quiz with both MCQ and TF questions."""
        self.client.force_login(self.instructor)
        deadline = timezone.now() + timedelta(days=5)

        questions = [
            {
                'question_text': 'Which algorithm uses elliptic curves?',
                'question_type': 'MCQ',
                'option_a': 'ECDSA',
                'option_b': 'DES',
                'option_c': 'MD5',
                'option_d': 'RC4',
                'correct_answer': 'A'
            },
            {
                'question_text': 'Is SHA-256 an encryption algorithm?',
                'question_type': 'TF',
                'correct_answer': 'False'
            }
        ]

        response = self.client.post(reverse('create_quiz'), {
            'title': 'Cryptography 101 Quiz',
            'description': 'Test covering asymmetric keys and hashing.',
            'time_limit_minutes': 25,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'CRY101',
            'questions_data': json.dumps(questions)
        })

        # Redirects to instructor dashboard
        self.assertRedirects(response, reverse('instructor_dashboard'))

        # Verify Quiz persisted with correct attributes
        quiz = Quiz.objects.get(access_pin='CRY101')
        self.assertEqual(quiz.title, 'Cryptography 101 Quiz')
        self.assertEqual(quiz.created_by, self.instructor)
        self.assertEqual(quiz.time_limit_minutes, 25)

        # Verify Questions persisted and associated with the quiz
        saved_questions = Question.objects.filter(quiz=quiz).order_by('id')
        self.assertEqual(saved_questions.count(), 2)

        q1 = saved_questions[0]
        self.assertEqual(q1.question_type, 'MCQ')
        self.assertEqual(q1.option_a, 'ECDSA')
        self.assertEqual(q1.option_b, 'DES')
        self.assertEqual(q1.option_c, 'MD5')
        self.assertEqual(q1.option_d, 'RC4')
        self.assertEqual(q1.correct_answer, 'A')

        q2 = saved_questions[1]
        self.assertEqual(q2.question_type, 'TF')
        self.assertEqual(q2.option_a, 'True')
        self.assertEqual(q2.option_b, 'False')
        self.assertIsNone(q2.option_c)
        self.assertIsNone(q2.option_d)
        self.assertEqual(q2.correct_answer, 'False')


class TakeQuizUnitAndIntegrationTests(TestCase):
    """
    Tests for Student Quiz Taking feature:
    - Role restrictions (only Students can access take_quiz and view results)
    - Quiz deadline validation (cannot take expired quiz)
    - Question rendering (MCQ options A-D, True/False options)
    - Server-side answer submission and automated grading
    - DSA digital signature generation and verification
    - Prevention of duplicate submissions
    - Student dashboard links and status display
    """
    def setUp(self):
        self.client = Client()
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        # Test instructor
        self.instructor = User(
            username='instructor_snape',
            email='severus@hogwarts.edu'
        )
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        # Test student
        self.student = User(
            username='student_hermione',
            email='hermione@hogwarts.edu'
        )
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)
        StudentProfile.objects.create(
            user=self.student,
            full_name='Hermione Granger',
            student_id='STU-9901'
        )

        # Another student
        self.other_student = User(
            username='student_ron',
            email='ron@hogwarts.edu'
        )
        self.other_student.set_unusable_password()
        self.other_student.save()
        self.other_student.groups.add(self.student_group)

        # Active test quiz
        self.quiz = Quiz.objects.create(
            title='Defense Against the Dark Arts Quiz',
            description='Test on counter-curses and cryptographic wards.',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(days=2),
            access_pin='DEF101',
            created_by=self.instructor
        )

        # MCQ Question
        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Which spell produces a patronus?',
            question_type='MCQ',
            option_a='Expelliarmus',
            option_b='Expecto Patronum',
            option_c='Lumos',
            option_d='Alohomora',
            correct_answer='B'
        )

        # TF Question
        self.q2 = Question.objects.create(
            quiz=self.quiz,
            question_text='Is Avada Kedavra an Unforgivable Curse?',
            question_type='TF',
            option_a='True',
            option_b='False',
            correct_answer='True'
        )

    def test_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated user attempting to take quiz or view results is redirected to login."""
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_instructor_denied_from_taking_quiz(self):
        """Instructor accessing take_quiz is denied with HTTP 403."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_student_can_render_quiz_and_questions(self):
        """Student can view the quiz interface with all questions and choices."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Defense Against the Dark Arts Quiz')
        self.assertContains(response, 'Which spell produces a patronus?')
        self.assertContains(response, 'Expecto Patronum')
        self.assertContains(response, 'Is Avada Kedavra an Unforgivable Curse?')
        self.assertContains(response, 'True')
        self.assertContains(response, 'False')
        self.assertContains(response, 'Submit Quiz Answers')

    def test_cannot_take_expired_quiz(self):
        """Attempting to access an expired quiz redirects with an error."""
        self.quiz.deadline = timezone.now() - timedelta(hours=1)
        self.quiz.save()

        self.client.force_login(self.student)
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_automatic_grading_and_dsa_signature(self):
        """Submitting answers correctly grades the quiz and signs the submission with DSA."""
        self.client.force_login(self.student)

        # Answer Q1 correctly (B) and Q2 correctly (True) -> 2/2 = 100%
        response = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'B',
            f'question_{self.q2.id}': 'True'
        })

        # Should create submission and redirect to results
        self.assertEqual(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).count(), 1)
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.score, 2.0)
        self.assertEqual(submission.percentage, 100.0)
        self.assertTrue(len(submission.dsa_signature) > 0)

        # Redirects to results page
        self.assertRedirects(response, reverse('quiz_result', args=[submission.id]))

        # Test results page rendering and DSA verification
        result_response = self.client.get(reverse('quiz_result', args=[submission.id]))
        self.assertEqual(result_response.status_code, 200)
        self.assertContains(result_response, '100%')
        self.assertContains(result_response, 'DSA Verified')

    def test_partial_score_grading(self):
        """Submitting 1 correct and 1 incorrect answer grades 1/2 (50%)."""
        self.client.force_login(self.student)

        # Answer Q1 incorrectly (A) and Q2 correctly (True) -> 1/2 = 50%
        self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
            f'question_{self.q2.id}': 'True'
        })

        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.score, 1.0)
        self.assertEqual(submission.percentage, 50.0)

    def test_duplicate_submission_prevented(self):
        """A student cannot submit the same quiz more than once."""
        self.client.force_login(self.student)

        # First submission
        self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'B',
            f'question_{self.q2.id}': 'True'
        })
        self.assertEqual(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).count(), 1)

        # Second attempt should be blocked and redirected
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertRedirects(response, reverse('quiz_result', args=[submission.id]))

        # Second POST should also be blocked and redirected to result without creating duplicate
        response2 = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
            f'question_{self.q2.id}': 'False'
        })
        self.assertRedirects(response2, reverse('quiz_result', args=[submission.id]))
        self.assertEqual(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).count(), 1)

    def test_student_cannot_view_other_student_results(self):
        """A student cannot access another student's quiz results."""
        self.client.force_login(self.student)
        self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'B',
            f'question_{self.q2.id}': 'True'
        })
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)

        # Other student attempts to access
        self.client.force_login(self.other_student)
        response = self.client.get(reverse('quiz_result', args=[submission.id]))
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_student_dashboard_displays_start_quiz_link(self):
        """Student dashboard includes a clickable Start Quiz link pointing to take_quiz."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('student_dashboard'))
        self.assertEqual(response.status_code, 200)
        expected_url = reverse('take_quiz', args=[self.quiz.id])
        self.assertContains(response, f'href="{expected_url}"')


class InstructorQuizResultsTests(TestCase):
    """
    Tests for Instructor Quiz Results feature:
    - Results access and role enforcement (only Instructors can access)
    - Quiz ownership enforcement (instructors may only view results for their own quizzes)
    - Displaying student results with scores, percentages, and dates
    - DSA cryptographic verification in results overview and detail
    - Graceful empty results handling for quizzes with no submissions
    - Instructor Dashboard Results button link
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

        # Instructor A (owner)
        self.instructor_a = User(username='instructor_a', email='a@uni.edu')
        self.instructor_a.set_unusable_password()
        self.instructor_a.save()
        self.instructor_a.groups.add(self.instructor_group)

        # Instructor B (non-owner)
        self.instructor_b = User(username='instructor_b', email='b@uni.edu')
        self.instructor_b.set_unusable_password()
        self.instructor_b.save()
        self.instructor_b.groups.add(self.instructor_group)

        # Student
        self.student = User(username='student_harry', email='harry@uni.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)
        StudentProfile.objects.create(
            user=self.student,
            full_name='Harry Potter',
            student_id='STU-HP01'
        )

        # Quiz created by Instructor A
        self.quiz = Quiz.objects.create(
            title='Advanced Potions Quiz',
            description='Test on Polyjuice and Felix Felicis.',
            time_limit_minutes=20,
            deadline=timezone.now() + timedelta(days=3),
            access_pin='POT999',
            created_by=self.instructor_a
        )

        # Question for the quiz
        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Which ingredient is needed for Polyjuice?',
            question_type='MCQ',
            option_a='Boomslang skin',
            option_b='Gillyweed',
            option_c='Mandrake leaf',
            option_d='Bezoar',
            correct_answer='A'
        )

    def test_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated user accessing quiz results or submission detail is redirected to login."""
        response = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_student_denied_from_instructor_results(self):
        """Student accessing instructor quiz results is denied with HTTP 403."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_quiz_ownership_enforced_for_results_view(self):
        """An instructor cannot view results for a quiz created by another instructor."""
        self.client.force_login(self.instructor_b)
        response = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_empty_results_handled_gracefully(self):
        """A quiz with no submissions renders cleanly without errors."""
        self.client.force_login(self.instructor_a)
        response = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Advanced Potions Quiz')
        self.assertContains(response, 'POT999')
        self.assertContains(response, 'No students have submitted this quiz yet.')
        self.assertEqual(response.context['total_submissions'], 0)
        self.assertIsNone(response.context['avg_percentage'])

    def test_instructor_can_view_student_results_and_dsa(self):
        """The quiz owner can view submitted results with score, student info, and DSA verification."""
        # Create a submission
        from quiz.crypto import generate_dsa_signature
        now = timezone.now()
        ts = now.isoformat()
        sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=1.0,
            percentage=100.0,
            timestamp_str=ts
        )
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            dsa_signature=sig
        )
        # Ensure timestamp matches for test
        submission.submitted_at = now
        submission.save(update_fields=['submitted_at'])

        self.client.force_login(self.instructor_a)
        response = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Advanced Potions Quiz')
        self.assertContains(response, 'POT999')
        self.assertContains(response, 'Harry Potter')
        self.assertContains(response, 'student_harry')
        self.assertContains(response, '100.0%')
        self.assertContains(response, 'DSA Verified')

        # Test individual submission detail view
        detail_response = self.client.get(reverse('instructor_submission_detail', args=[submission.id]))
        self.assertEqual(detail_response.status_code, 200)
        self.assertContains(detail_response, 'Harry Potter')
        self.assertContains(detail_response, 'STU-HP01')
        self.assertContains(detail_response, 'Boomslang skin')
        self.assertContains(detail_response, 'DSA Signature')

    def test_quiz_ownership_enforced_for_submission_detail(self):
        """An instructor cannot view submission details for a quiz created by another instructor."""
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            dsa_signature="dummy"
        )
        self.client.force_login(self.instructor_b)
        response = self.client.get(reverse('instructor_submission_detail', args=[submission.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_instructor_dashboard_results_link(self):
        """The Instructor Dashboard contains a proper link to the quiz results page."""
        self.client.force_login(self.instructor_a)
        response = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(response.status_code, 200)
        expected_url = reverse('instructor_quiz_results', args=[self.quiz.id])
        self.assertContains(response, f'href="{expected_url}"')


