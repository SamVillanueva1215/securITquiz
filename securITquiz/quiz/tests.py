import json
from datetime import timedelta
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.urls import reverse

from quiz.models import StudentProfile, Quiz, Question, QuizSubmission
from quiz.forms import QuizForm, validate_questions_data, generate_secure_pin
from quiz.crypto import generate_dsa_signature, verify_dsa_signature


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


class CreateQuizUnitAndIntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()

        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.instructor = User.objects.create_user(
            username='instructor_carol',
            email='carol@university.edu',
            password='SecretPassword123!'
        )
        self.instructor.groups.add(self.instructor_group)

        self.student = User.objects.create_user(
            username='student_dave',
            email='dave@university.edu',
            password='SecretPassword123!'
        )
        self.student.groups.add(self.student_group)

    def test_pin_generator_format_and_uniqueness(self):
        """Test the 6-character alphanumeric PIN generation."""
        pin = generate_secure_pin()
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isalnum())
        self.assertTrue(pin.isupper())

        Quiz.objects.create(
            title="Existing Quiz",
            time_limit_minutes=10,
            deadline=timezone.now() + timedelta(days=1),
            access_pin=pin,
            created_by=self.instructor
        )
        new_pin = generate_secure_pin()
        self.assertNotEqual(pin, new_pin)

    def test_validate_questions_data_empty(self):
        """At least one question is required."""
        val, errors = validate_questions_data([])
        self.assertEqual(len(val), 0)
        self.assertIn("At least one question is required", errors[0])

    def test_validate_questions_data_valid_mcq(self):
        """Validate MCQ questions requiring 4 options and valid choice."""
        raw = [{
            'question_text': 'What is RSA?',
            'question_type': 'MCQ',
            'option_a': 'Asymmetric cipher',
            'option_b': 'Symmetric cipher',
            'option_c': 'Hash function',
            'option_d': 'Block mode',
            'correct_answer': 'A'
        }]
        val, errors = validate_questions_data(raw)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(val), 1)
        self.assertEqual(val[0]['correct_answer'], 'A')

    def test_validate_questions_data_invalid_mcq(self):
        """MCQ missing an option or valid correct answer should fail."""
        raw = [{
            'question_text': 'Incomplete MCQ',
            'question_type': 'MCQ',
            'option_a': 'Option A',
            'option_b': 'Option B',
            'option_c': '',
            'option_d': 'Option D',
            'correct_answer': 'E'
        }]
        val, errors = validate_questions_data(raw)
        self.assertTrue(len(errors) >= 2)

    def test_validate_questions_data_valid_true_false(self):
        """Validate True/False question format."""
        raw = [{
            'question_text': 'AES is a symmetric cipher.',
            'question_type': 'TF',
            'correct_answer': 'True'
        }]
        val, errors = validate_questions_data(raw)
        self.assertEqual(len(errors), 0)
        self.assertEqual(val[0]['correct_answer'], 'True')
        self.assertEqual(val[0]['option_a'], 'True')
        self.assertEqual(val[0]['option_b'], 'False')

    def test_validate_questions_data_invalid_true_false(self):
        """True/False question with invalid answer option should fail."""
        raw = [{
            'question_text': 'AES is symmetric.',
            'question_type': 'TF',
            'correct_answer': 'Maybe'
        }]
        val, errors = validate_questions_data(raw)
        self.assertTrue(len(errors) >= 1)

    def test_student_denied_from_creating_quiz(self):
        """A student attempting to access create_quiz is blocked with HTTP 403."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('create_quiz'))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_instructor_can_render_create_quiz_form(self):
        """Instructor can load the quiz creation page."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('create_quiz'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create New Quiz')
        self.assertContains(response, 'id_access_pin')

    def test_create_quiz_and_questions_atomic_success(self):
        """Full flow: Instructor posts quiz and multiple questions; saved atomically."""
        self.client.force_login(self.instructor)

        deadline = timezone.now() + timedelta(days=7)
        questions_payload = [
            {
                'question_text': 'Which algorithm uses elliptic curves?',
                'question_type': 'MCQ',
                'option_a': 'ECDSA',
                'option_b': 'AES',
                'option_c': 'DES',
                'option_d': 'MD5',
                'correct_answer': 'A'
            },
            {
                'question_text': 'SHA-256 is an encryption algorithm.',
                'question_type': 'TF',
                'correct_answer': 'False'
            }
        ]

        post_data = {
            'title': 'Applied Cryptography Quiz 1',
            'description': 'Midterm exam covering ciphers and hashing.',
            'time_limit_minutes': 30,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'CRYP01',
            'questions_data': json.dumps(questions_payload)
        }

        response = self.client.post(reverse('create_quiz'), post_data)
        self.assertRedirects(response, reverse('instructor_dashboard'))

        quiz = Quiz.objects.get(title='Applied Cryptography Quiz 1')
        self.assertEqual(quiz.created_by, self.instructor)
        self.assertEqual(quiz.access_pin, 'CRYP01')
        self.assertEqual(quiz.questions.count(), 2)

        q1 = quiz.questions.get(question_text='Which algorithm uses elliptic curves?')
        self.assertEqual(q1.question_type, 'MCQ')
        self.assertEqual(q1.correct_answer, 'A')

        q2 = quiz.questions.get(question_text='SHA-256 is an encryption algorithm.')
        self.assertEqual(q2.question_type, 'TF')
        self.assertEqual(q2.correct_answer, 'False')

    def test_create_quiz_without_questions_fails(self):
        """Submitting a quiz without questions rolls back and creates no Quiz."""
        self.client.force_login(self.instructor)

        deadline = timezone.now() + timedelta(days=2)
        post_data = {
            'title': 'Empty Quiz',
            'time_limit_minutes': 15,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'EMPTY1',
            'questions_data': json.dumps([])
        }

        response = self.client.post(reverse('create_quiz'), post_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'At least one question is required')
        self.assertFalse(Quiz.objects.filter(title='Empty Quiz').exists())

    def test_atomic_rollback_on_question_error(self):
        """If one question fails server-side validation, no quiz or questions are saved."""
        self.client.force_login(self.instructor)

        deadline = timezone.now() + timedelta(days=2)
        questions_payload = [
            {
                'question_text': 'Valid Question',
                'question_type': 'TF',
                'correct_answer': 'True'
            },
            {
                'question_text': '',  # Invalid empty question
                'question_type': 'MCQ',
                'option_a': 'A',
                'option_b': 'B',
                'option_c': 'C',
                'option_d': 'D',
                'correct_answer': 'A'
            }
        ]

        post_data = {
            'title': 'Failing Atomic Quiz',
            'time_limit_minutes': 20,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'FAIL01',
            'questions_data': json.dumps(questions_payload)
        }

        response = self.client.post(reverse('create_quiz'), post_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Question text cannot be empty')
        self.assertFalse(Quiz.objects.filter(title='Failing Atomic Quiz').exists())
        self.assertFalse(Question.objects.filter(question_text='Valid Question').exists())


class TakeQuizUnitAndIntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()

        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.instructor = User(username='instructor_snape', email='severus@hogwarts.edu')
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        self.student = User(username='student_hermione', email='hermione@hogwarts.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)
        StudentProfile.objects.create(
            user=self.student,
            full_name='Hermione Granger',
            student_id='STU-HG01'
        )

        self.other_student = User(username='student_ron', email='ron@hogwarts.edu')
        self.other_student.set_unusable_password()
        self.other_student.save()
        self.other_student.groups.add(self.student_group)

        self.quiz = Quiz.objects.create(
            title='Defense Against the Dark Arts Quiz',
            description='Final examination on counter-curses and defensive charms.',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(days=2),
            access_pin='DADA01',
            created_by=self.instructor
        )

        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Which spell produces a patronus?',
            question_type='MCQ',
            option_a='Expelliarmus',
            option_b='Expecto Patronum',
            option_c='Lumos',
            option_d='Stupefy',
            correct_answer='B'
        )

        self.q2 = Question.objects.create(
            quiz=self.quiz,
            question_text='Is Avada Kedavra an Unforgivable Curse?',
            question_type='TF',
            option_a='True',
            option_b='False',
            correct_answer='True'
        )

    def _authorize_pin_session(self, user=None):
        """Helper to simulate successful PIN verification for take_quiz."""
        user = user or self.student
        session = self.client.session
        session[f'verified_quiz_{self.quiz.id}_user_{user.id}'] = True
        session.save()

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
        """Student with verified PIN can view the quiz interface with all questions and choices."""
        self.client.force_login(self.student)
        self._authorize_pin_session()
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
        self._authorize_pin_session()
        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_automatic_grading_and_dsa_signature(self):
        """Submitting answers correctly grades the quiz and signs the submission with DSA (version 2)."""
        self.client.force_login(self.student)
        self._authorize_pin_session()

        # Answer Q1 correctly (B) and Q2 correctly (True) -> 2/2 = 100%
        response = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'B',
            f'question_{self.q2.id}': 'True'
        })

        self.assertEqual(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).count(), 1)
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.score, 2.0)
        self.assertEqual(submission.percentage, 100.0)
        self.assertEqual(submission.signature_version, 2)
        self.assertTrue(len(submission.dsa_signature) > 0)

        # Redirects to results page
        self.assertRedirects(response, reverse('quiz_result', args=[submission.id]))

        # Test results page rendering and DSA verification
        result_response = self.client.get(reverse('quiz_result', args=[submission.id]))
        self.assertEqual(result_response.status_code, 200)
        self.assertContains(result_response, '100%')
        self.assertContains(result_response, 'DSA Verified')
        self.assertContains(result_response, 'Version 2')

    def test_partial_score_grading(self):
        """Submitting 1 correct and 1 incorrect answer grades 1/2 (50%)."""
        self.client.force_login(self.student)
        self._authorize_pin_session()

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
        self._authorize_pin_session()

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
        self._authorize_pin_session()
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
        """Student dashboard includes a clickable Start Quiz link pointing to verify_quiz_pin."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('student_dashboard'))
        self.assertEqual(response.status_code, 200)
        expected_url = reverse('verify_quiz_pin', args=[self.quiz.id])
        self.assertContains(response, f'href="{expected_url}"')


class InstructorQuizResultsTests(TestCase):
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
        now = timezone.now()
        ts = now.isoformat()
        sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=1.0,
            percentage=100.0,
            timestamp_str=ts,
            signature_version=1
        )
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers={'1': 'A'},
            signature_version=1,
            dsa_signature=sig
        )
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


class EditQuizUnitAndIntegrationTests(TestCase):
    """
    Tests for Feature A: Edit Quiz
    - Connect Edit button on instructor dashboard
    - View protected by @instructor_required
    - Enforce quiz ownership (quiz.created_by == request.user)
    - Prepopulates edit form with title, description, time limit, deadline, questions
    - Supports updating questions, adding questions, deleting questions, changing types
    - Preserves access PIN
    - Saves changes atomically with transaction.atomic
    - Preserves existing student submissions and DSA verification
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

        self.instructor_owner = User(username='prof_mcgonagall', email='minerva@hogwarts.edu')
        self.instructor_owner.set_unusable_password()
        self.instructor_owner.save()
        self.instructor_owner.groups.add(self.instructor_group)

        self.instructor_other = User(username='prof_flitwick', email='filius@hogwarts.edu')
        self.instructor_other.set_unusable_password()
        self.instructor_other.save()
        self.instructor_other.groups.add(self.instructor_group)

        self.student = User(username='student_neville', email='neville@hogwarts.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)

        self.quiz = Quiz.objects.create(
            title='Transfiguration Fundamentals',
            description='First term exam on inanimate-to-inanimate transformation.',
            time_limit_minutes=25,
            deadline=timezone.now() + timedelta(days=5),
            access_pin='TRN101',
            created_by=self.instructor_owner
        )

        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='What is the primary incantation to turn a match into a needle?',
            question_type='MCQ',
            option_a='Avifors',
            option_b='Acus Transformatio',
            option_c='Vera Verto',
            option_d='Evanesco',
            correct_answer='B'
        )

        self.q2 = Question.objects.create(
            quiz=self.quiz,
            question_text='Transfiguration is an exact science.',
            question_type='TF',
            option_a='True',
            option_b='False',
            correct_answer='True'
        )

    def test_edit_button_present_on_dashboard(self):
        """The instructor dashboard Edit button links to the edit_quiz URL."""
        self.client.force_login(self.instructor_owner)
        response = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(response.status_code, 200)
        expected_url = reverse('edit_quiz', args=[self.quiz.id])
        self.assertContains(response, f'href="{expected_url}"')

    def test_unauthenticated_user_redirected_from_edit(self):
        """Unauthenticated user accessing edit_quiz is redirected to login."""
        response = self.client.get(reverse('edit_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_student_denied_from_edit_quiz(self):
        """Student accessing edit_quiz is denied with HTTP 403."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('edit_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_non_owner_instructor_denied_from_edit_quiz(self):
        """An instructor who did not create the quiz is denied with HTTP 403."""
        self.client.force_login(self.instructor_other)
        response = self.client.get(reverse('edit_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_owner_can_load_prepopulated_edit_page(self):
        """Quiz owner can render edit_quiz with prepopulated values and questions."""
        self.client.force_login(self.instructor_owner)
        response = self.client.get(reverse('edit_quiz', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Edit Quiz: Transfiguration Fundamentals')
        self.assertContains(response, 'TRN101')
        self.assertContains(response, 'What is the primary incantation to turn a match into a needle?')
        self.assertContains(response, 'Transfiguration is an exact science.')

    def test_owner_can_update_quiz_metadata_and_questions(self):
        """Owner can update quiz title, description, time limit, and modify questions."""
        self.client.force_login(self.instructor_owner)

        deadline = self.quiz.deadline
        updated_questions = [
            # Updated existing question 1
            {
                'id': self.q1.id,
                'question_text': 'Updated: Match to needle spell?',
                'question_type': 'MCQ',
                'option_a': 'Avifors',
                'option_b': 'Acus Transformatio',
                'option_c': 'Vera Verto',
                'option_d': 'Evanesco',
                'correct_answer': 'B'
            },
            # Newly added Identification question
            {
                'id': None,
                'question_text': 'Identify the branch of magic that deals with alteration of form:',
                'question_type': 'ID',
                'correct_answer': 'Transfiguration'
            }
            # Question 2 was removed!
        ]

        post_data = {
            'title': 'Advanced Transfiguration Examination',
            'description': 'Updated description.',
            'time_limit_minutes': 45,
            'deadline': deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': 'TRN101',  # Preserved PIN
            'questions_data': json.dumps(updated_questions)
        }

        response = self.client.post(reverse('edit_quiz', args=[self.quiz.id]), post_data)
        self.assertRedirects(response, reverse('instructor_dashboard'))

        self.quiz.refresh_from_db()
        self.assertEqual(self.quiz.title, 'Advanced Transfiguration Examination')
        self.assertEqual(self.quiz.description, 'Updated description.')
        self.assertEqual(self.quiz.time_limit_minutes, 45)
        self.assertEqual(self.quiz.access_pin, 'TRN101')

        # Check questions: 2 questions total (q1 updated, new question added, q2 deleted)
        self.assertEqual(self.quiz.questions.count(), 2)

        self.q1.refresh_from_db()
        self.assertEqual(self.q1.question_text, 'Updated: Match to needle spell?')

        self.assertFalse(Question.objects.filter(id=self.q2.id).exists())

        new_q = self.quiz.questions.get(question_type='ID')
        self.assertEqual(new_q.question_text, 'Identify the branch of magic that deals with alteration of form:')
        self.assertEqual(new_q.correct_answer, 'Transfiguration')

    def test_edit_preserves_historical_submissions_and_dsa(self):
        """Editing a quiz must not delete or invalidate existing student submissions or DSA signatures."""
        # Create an existing submission before edit
        now = timezone.now()
        ts = now.isoformat()
        sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=2.0,
            percentage=100.0,
            timestamp_str=ts,
            signature_version=1
        )
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=2.0,
            percentage=100.0,
            answers={str(self.q1.id): 'B', str(self.q2.id): 'True'},
            signature_version=1,
            dsa_signature=sig
        )
        submission.submitted_at = now
        submission.save(update_fields=['submitted_at'])

        # Now edit the quiz
        self.client.force_login(self.instructor_owner)
        updated_questions = [
            {
                'id': self.q1.id,
                'question_text': self.q1.question_text,
                'question_type': 'MCQ',
                'option_a': self.q1.option_a,
                'option_b': self.q1.option_b,
                'option_c': self.q1.option_c,
                'option_d': self.q1.option_d,
                'correct_answer': 'B'
            }
        ]
        post_data = {
            'title': 'Transfiguration Fundamentals (Edited)',
            'description': self.quiz.description,
            'time_limit_minutes': 30,
            'deadline': self.quiz.deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': self.quiz.access_pin,
            'questions_data': json.dumps(updated_questions)
        }
        self.client.post(reverse('edit_quiz', args=[self.quiz.id]), post_data)

        # Submission still exists intact
        submission.refresh_from_db()
        self.assertEqual(submission.score, 2.0)
        self.assertEqual(submission.percentage, 100.0)

        # DSA signature remains 100% valid
        is_valid = verify_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=submission.score,
            percentage=submission.percentage,
            timestamp_str=submission.submitted_at.isoformat(),
            hex_signature=submission.dsa_signature,
            answers=submission.answers,
            signature_version=submission.signature_version
        )
        self.assertTrue(is_valid)

    def test_edit_quiz_fails_if_all_questions_removed(self):
        """An edit that attempts to delete all questions fails with a validation error."""
        self.client.force_login(self.instructor_owner)
        post_data = {
            'title': self.quiz.title,
            'description': self.quiz.description,
            'time_limit_minutes': 20,
            'deadline': self.quiz.deadline.strftime('%Y-%m-%dT%H:%M'),
            'access_pin': self.quiz.access_pin,
            'questions_data': json.dumps([])
        }
        response = self.client.post(reverse('edit_quiz', args=[self.quiz.id]), post_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'At least one question is required')
        # Existing questions preserved
        self.assertEqual(self.quiz.questions.count(), 2)


class IdentificationQuestionTests(TestCase):
    """
    Tests for Feature B: Identification Question Type
    - Question type 'ID' supported in models, forms, views, and templates
    - Identification questions require text and correct_answer (options A-D null)
    - Take Quiz renders text input
    - Grading: case-insensitive, strip leading/trailing whitespace
    - Correct answer scores 1.0, incorrect scores 0.0
    - Answer dictionary stored in QuizSubmission.answers
    - Results and review pages display student answer, expected answer, status
    """
    def setUp(self):
        self.client = Client()
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.instructor = User(username='prof_flitwick2', email='flitwick@hogwarts.edu')
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        self.student = User(username='student_luna', email='luna@hogwarts.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)

        self.quiz = Quiz.objects.create(
            title='Charms Identification Quiz',
            description='Test your knowledge of spell incantations.',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(days=3),
            access_pin='CHM202',
            created_by=self.instructor
        )

        self.q_id1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Name the charm used to make objects levitate:',
            question_type='ID',
            correct_answer='Wingardium Leviosa'
        )

        self.q_id2 = Question.objects.create(
            quiz=self.quiz,
            question_text='Name the charm that produces light from the wand tip:',
            question_type='ID',
            correct_answer='Lumos'
        )

    def _authorize_pin_session(self):
        session = self.client.session
        session[f'verified_quiz_{self.quiz.id}_user_{self.student.id}'] = True
        session.save()

    def test_validation_requires_correct_answer_for_id(self):
        """Identification question requires question text and expected answer."""
        val, errors = validate_questions_data([{
            'question_text': 'Identify this term:',
            'question_type': 'ID',
            'correct_answer': ''
        }])
        self.assertTrue(len(errors) > 0)
        self.assertIn('correct answer is required', errors[0])

    def test_student_answers_identification_case_insensitive_and_whitespace(self):
        """Identification grading is case-insensitive and trims surrounding whitespace."""
        self.client.force_login(self.student)
        self._authorize_pin_session()

        # Submit answers with mixed case and extra whitespace:
        # Q1: "   wingardium leviosa   " matches "Wingardium Leviosa"
        # Q2: "  LUMOS  " matches "Lumos"
        response = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q_id1.id}': '   wingardium leviosa   ',
            f'question_{self.q_id2.id}': '  LUMOS  '
        })

        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.score, 2.0)
        self.assertEqual(submission.percentage, 100.0)
        self.assertEqual(submission.answers[str(self.q_id1.id)], 'wingardium leviosa')
        self.assertEqual(submission.answers[str(self.q_id2.id)], 'LUMOS')

    def test_student_answers_identification_incorrect(self):
        """Incorrect Identification answers receive 0 points."""
        self.client.force_login(self.student)
        self._authorize_pin_session()

        response = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q_id1.id}': 'Alohomora',  # Wrong answer
            f'question_{self.q_id2.id}': 'lumos'        # Correct answer
        })

        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.score, 1.0)
        self.assertEqual(submission.percentage, 50.0)

    def test_identification_review_displayed_in_results(self):
        """Results and review page displays the student's submitted answer and expected answer."""
        self.client.force_login(self.student)
        self._authorize_pin_session()

        self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q_id1.id}': 'Wingardium Leviosa',
            f'question_{self.q_id2.id}': 'Nox'  # Wrong answer
        })
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)

        # Release results so student can view detailed review
        self.quiz.results_released = True
        self.quiz.save()

        # Student result review
        response = self.client.get(reverse('quiz_result', args=[submission.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Identification')
        self.assertContains(response, 'Wingardium Leviosa')
        self.assertContains(response, 'Nox')
        self.assertContains(response, 'Correct')
        self.assertContains(response, 'Incorrect')

        # Instructor submission detail review
        self.client.force_login(self.instructor)
        detail_response = self.client.get(reverse('instructor_submission_detail', args=[submission.id]))
        self.assertEqual(detail_response.status_code, 200)
        self.assertContains(detail_response, 'Identification')
        self.assertContains(detail_response, 'Nox')
        self.assertContains(detail_response, 'Lumos')


class AccessPinVerificationTests(TestCase):
    """
    Tests for Feature C: Access PIN Verification Before Starting Quiz
    - Start Quiz button on dashboard opens verify_quiz_pin
    - verify_quiz_pin view renders quiz info and PIN input
    - Incorrect PIN fails validation without revealing the PIN
    - Correct PIN sets session authorization and redirects to take_quiz
    - Direct access to take_quiz without prior PIN verification is blocked and redirected
    - Submission clears the session PIN authorization
    - Expired or already submitted quiz redirects appropriately
    """
    def setUp(self):
        self.client = Client()
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.instructor = User(username='instructor_sprout', email='pomona@hogwarts.edu')
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        self.student = User(username='student_ginny', email='ginny@hogwarts.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)

        self.quiz = Quiz.objects.create(
            title='Herbology Midterm Examination',
            description='Mandrakes, Devil Snare, and Gillyweed questions.',
            time_limit_minutes=20,
            deadline=timezone.now() + timedelta(days=4),
            access_pin='HRB404',
            created_by=self.instructor
        )

        self.q = Question.objects.create(
            quiz=self.quiz,
            question_text='What ear protection is needed for Mandrakes?',
            question_type='ID',
            correct_answer='Earmuffs'
        )

    def test_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated user accessing PIN verification is redirected to login."""
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_instructor_denied_from_pin_verification(self):
        """Instructor accessing student PIN verification is denied with HTTP 403."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Access Denied', status_code=403)

    def test_student_can_render_pin_verification_page(self):
        """Student can view the PIN verification form with quiz title, description, time limit."""
        self.client.force_login(self.student)
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Herbology Midterm Examination')
        self.assertContains(response, 'Mandrakes, Devil Snare, and Gillyweed')
        self.assertContains(response, 'Enter 6-Character Access PIN')
        self.assertNotContains(response, 'HRB404')  # Must NEVER reveal the PIN to the student!

    def test_incorrect_pin_rejected_with_error(self):
        """Submitting an invalid PIN fails and shows error without revealing the PIN."""
        self.client.force_login(self.student)
        response = self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {
            'access_pin': 'WRONG1'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid Access PIN')
        self.assertNotContains(response, 'HRB404')

        # Session flag should not be set
        session_key = f'verified_quiz_{self.quiz.id}_user_{self.student.id}'
        self.assertFalse(self.client.session.get(session_key, False))

    def test_correct_pin_authorizes_session_and_redirects(self):
        """Submitting the correct PIN sets session flag and redirects to take_quiz."""
        self.client.force_login(self.student)
        response = self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {
            'access_pin': 'hrb404'  # Case-insensitive
        })
        self.assertRedirects(response, reverse('take_quiz', args=[self.quiz.id]))

        # Session flag should be authorized
        session_key = f'verified_quiz_{self.quiz.id}_user_{self.student.id}'
        self.assertTrue(self.client.session.get(session_key))

    def test_direct_bypass_to_take_quiz_blocked(self):
        """Attempting to access take_quiz directly without PIN verification redirects to verify_quiz_pin."""
        self.client.force_login(self.student)
        # Ensure session flag is NOT set
        session = self.client.session
        session.pop(f'verified_quiz_{self.quiz.id}_user_{self.student.id}', None)
        session.save()

        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertRedirects(response, reverse('verify_quiz_pin', args=[self.quiz.id]))

    def test_submitting_quiz_clears_session_pin_authorization(self):
        """Submitting a quiz clears the session flag so subsequent take attempts are gated."""
        self.client.force_login(self.student)
        # Authorize via PIN first
        self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {
            'access_pin': 'HRB404'
        })
        session_key = f'verified_quiz_{self.quiz.id}_user_{self.student.id}'
        self.assertTrue(self.client.session.get(session_key))

        # Submit answers
        self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q.id}': 'Earmuffs'
        })

        # Session authorization is removed
        self.assertFalse(self.client.session.get(session_key, False))

    def test_cannot_verify_pin_for_expired_quiz(self):
        """Expired quiz redirects back to student dashboard."""
        self.quiz.deadline = timezone.now() - timedelta(days=1)
        self.quiz.save()

        self.client.force_login(self.student)
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_already_submitted_quiz_redirects_from_pin_verification(self):
        """If a student has already submitted, verify_quiz_pin redirects to quiz_result."""
        QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            dsa_signature="dummy"
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertRedirects(response, reverse('quiz_result', args=[submission.id]))


class DsaSignatureVersioningAndIntegrityTests(TestCase):
    """
    Tests for DSA Signature Versioning (v1 and v2) and Non-Repudiation:
    - Version 1 signatures (legacy): hash student, quiz, score, percentage, timestamp.
    - Version 2 signatures (new): hash student, quiz, score, percentage, answers, timestamp.
    - Backward compatibility: Existing v1 signatures remain valid.
    - Answer tampering protection: Any alteration to submitted answers invalidates v2 signatures.
    - Score/metadata tampering protection: Any alteration to score/user/quiz invalidates signatures.
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

        self.instructor = User(username='prof_vector', email='septima@hogwarts.edu')
        self.instructor.set_unusable_password()
        self.instructor.save()
        self.instructor.groups.add(self.instructor_group)

        self.student = User(username='student_cho', email='cho@hogwarts.edu')
        self.student.set_unusable_password()
        self.student.save()
        self.student.groups.add(self.student_group)

        self.quiz = Quiz.objects.create(
            title='Arithmancy Signature Test Quiz',
            description='Testing cryptographic signature versions.',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(days=3),
            access_pin='ARTH01',
            created_by=self.instructor
        )

        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='What is the magical property of number seven?',
            question_type='ID',
            correct_answer='Most powerfully magical number'
        )

    def test_v1_legacy_signature_verifies_successfully(self):
        """Historical v1 submissions without answers hash verify successfully."""
        now = timezone.now()
        ts = now.isoformat()
        v1_sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=1.0,
            percentage=100.0,
            timestamp_str=ts,
            signature_version=1
        )
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers={'1': 'Some answer'},
            signature_version=1,
            dsa_signature=v1_sig
        )
        submission.submitted_at = now
        submission.save(update_fields=['submitted_at'])

        is_valid = verify_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=submission.score,
            percentage=submission.percentage,
            timestamp_str=submission.submitted_at.isoformat(),
            hex_signature=submission.dsa_signature,
            answers=submission.answers,
            signature_version=submission.signature_version
        )
        self.assertTrue(is_valid)

    def test_v1_tampering_with_score_fails_verification(self):
        """Tampering with score on a v1 submission fails verification."""
        now = timezone.now()
        ts = now.isoformat()
        v1_sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=1.0,
            percentage=100.0,
            timestamp_str=ts,
            signature_version=1
        )
        is_valid = verify_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=2.0,  # Tampered score
            percentage=100.0,
            timestamp_str=ts,
            hex_signature=v1_sig,
            signature_version=1
        )
        self.assertFalse(is_valid)

    def test_v2_signature_protects_answers_from_tampering(self):
        """In v2 signatures, altering submitted answers in the database invalidates the DSA signature."""
        now = timezone.now()
        ts = now.isoformat()
        original_answers = {str(self.q1.id): 'Most powerfully magical number'}
        v2_sig = generate_dsa_signature(
            student_username=self.student.username,
            quiz_id=self.quiz.id,
            score=1.0,
            percentage=100.0,
            timestamp_str=ts,
            answers=original_answers,
            signature_version=2
        )
        submission = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers=original_answers,
            signature_version=2,
            dsa_signature=v2_sig
        )
        submission.submitted_at = now
        submission.save(update_fields=['submitted_at'])

        # Verify initial valid state
        self.assertTrue(verify_dsa_signature(
            student_username=submission.student.username,
            quiz_id=submission.quiz.id,
            score=submission.score,
            percentage=submission.percentage,
            timestamp_str=submission.submitted_at.isoformat(),
            hex_signature=submission.dsa_signature,
            answers=submission.answers,
            signature_version=submission.signature_version
        ))

        # Now simulate tampering with answers in DB
        tampered_answers = {str(self.q1.id): 'Tampered Answer'}
        is_valid_after_tampering = verify_dsa_signature(
            student_username=submission.student.username,
            quiz_id=submission.quiz.id,
            score=submission.score,
            percentage=submission.percentage,
            timestamp_str=submission.submitted_at.isoformat(),
            hex_signature=submission.dsa_signature,
            answers=tampered_answers,
            signature_version=submission.signature_version
        )
        self.assertFalse(is_valid_after_tampering)

    def test_new_quiz_submission_uses_v2_signature(self):
        """New student submissions automatically use signature_version=2 and include answers in verification."""
        self.client.force_login(self.student)
        # Authorize via PIN
        session = self.client.session
        session[f'verified_quiz_{self.quiz.id}_user_{self.student.id}'] = True
        session.save()

        response = self.client.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'Most powerfully magical number'
        })
        submission = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(submission.signature_version, 2)
        self.assertIn(str(self.q1.id), submission.answers)

        # Verify signature on results page
        res = self.client.get(reverse('quiz_result', args=[submission.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'DSA Verified')
        self.assertContains(res, 'Version 2')
        self.assertContains(res, 'Cryptographically protects submitted answers')


from datetime import timedelta
from django.contrib.sessions.models import Session
from quiz.models import ActiveSession, QuizAttempt, AuditLog
from quiz.crypto import KeyManagementError, get_dsa_private_key


class SingleActiveSessionTests(TestCase):
    """
    Tests for Part 2: Single Active Session Protection across Students and Instructors.
    """
    def setUp(self):
        self.password = 'StrongPass123!'
        self.student = User.objects.create_user(
            username='student_alice',
            email='alice@hogwarts.edu',
            password=self.password
        )
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

        self.instructor = User.objects.create_user(
            username='prof_flitwick',
            email='flitwick@hogwarts.edu',
            password=self.password
        )
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)

    def test_first_login_establishes_active_session(self):
        """First device login establishes ActiveSession record."""
        response = self.client.post(reverse('login'), {
            'username': 'student_alice',
            'password': self.password
        })
        self.assertRedirects(response, reverse('student_dashboard'))
        self.assertTrue(ActiveSession.objects.filter(user=self.student).exists())
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, self.client.session.session_key)

    def test_second_device_receives_conflict_warning(self):
        """Second device login detects active session and presents conflict warning without silent takeover."""
        # Device 1 logs in
        client1 = Client()
        client1.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        original_key = ActiveSession.objects.get(user=self.student).session_key

        # Device 2 attempts login
        client2 = Client()
        response = client2.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'quiz/device_conflict.html')
        self.assertContains(response, 'Active Session Detected')
        self.assertContains(response, 'Would you like to continue here and end the existing session?')

        # Device 1 session remains active
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, original_key)

    def test_confirm_device_switch_terminates_old_and_authorizes_new(self):
        """Confirming device switch invalidates the old device session and establishes the new device session."""
        client1 = Client()
        client1.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        old_key = ActiveSession.objects.get(user=self.student).session_key

        client2 = Client()
        # Device 2 initiates login and gets conflict
        client2.post(reverse('login'), {'username': 'student_alice', 'password': self.password})

        # Device 2 confirms device switch
        confirm_res = client2.post(reverse('confirm_device_switch'))
        self.assertRedirects(confirm_res, reverse('student_dashboard'))

        # ActiveSession should now have client2's key
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, client2.session.session_key)
        self.assertNotEqual(active.session_key, old_key)

        # Old session in Django Session table was deleted
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())

    def test_cancel_device_switch_preserves_original_session(self):
        """Cancelling device switch preserves original active session."""
        client1 = Client()
        client1.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        original_key = ActiveSession.objects.get(user=self.student).session_key

        client2 = Client()
        client2.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        cancel_res = client2.post(reverse('cancel_device_switch'))
        self.assertRedirects(cancel_res, reverse('login'))

        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, original_key)

    def test_logout_releases_active_session(self):
        """Logging out cleanly deletes ActiveSession record."""
        self.client.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertTrue(ActiveSession.objects.filter(user=self.student).exists())

        self.client.get(reverse('logout'))
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

    def test_inactivity_expiration_after_30_minutes(self):
        """Middleware automatically expires active session after 30 minutes of inactivity."""
        self.client.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        active = ActiveSession.objects.get(user=self.student)

        # Simulate 31 minutes of inactivity
        active.last_activity = timezone.now() - timedelta(minutes=31)
        active.save()

        # Access an authenticated view
        response = self.client.get(reverse('student_dashboard'))
        self.assertRedirects(response, reverse('login'))
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

    def test_independent_accounts_active_simultaneously(self):
        """Different accounts can maintain independent active sessions without conflict."""
        client_student = Client()
        res_s = client_student.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertEqual(res_s.status_code, 302)

        client_inst = Client()
        res_i = client_inst.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})
        self.assertEqual(res_i.status_code, 302)

        self.assertEqual(ActiveSession.objects.count(), 2)

    def test_instructor_single_session_protection(self):
        """Single Active Session protection applies equally to Instructors."""
        client1 = Client()
        client1.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})

        client2 = Client()
        res2 = client2.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})
        self.assertEqual(res2.status_code, 200)
        self.assertTemplateUsed(res2, 'quiz/device_conflict.html')


class ExaminationSecurityAndLifecycleTests(TestCase):
    """
    Tests for Part 4: Examination Security, PIN re-verification on refresh,
    timer persistence, answer locking, and server-side timeouts.
    """
    def setUp(self):
        self.student = User.objects.create_user(username='stu_cedric', email='cedric@hogwarts.edu', password='Pass')
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

        self.instructor = User.objects.create_user(username='prof_sprout', email='sprout@hogwarts.edu', password='Pass')
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)

        self.quiz = Quiz.objects.create(
            title='Herbology Timed Exam',
            access_pin='PLANT7',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(hours=2),
            passing_percentage=60.0,
            is_active=True,
            created_by=self.instructor
        )
        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Devil Snare hates sunlight.',
            question_type='TF',
            option_a='True',
            option_b='False',
            correct_answer='True'
        )
        self.q2 = Question.objects.create(
            quiz=self.quiz,
            question_text='What plant revives petrified victims?',
            question_type='ID',
            correct_answer='Mandrake'
        )

    def test_refresh_requires_pin_reverification(self):
        """When a student refreshes take_quiz, PIN verification is required again while attempt is preserved."""
        self.client.force_login(self.student)
        # Verify PIN first
        self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'PLANT7'})

        # First load of take_quiz renders successfully
        first_load = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(first_load.status_code, 200)
        self.assertTrue(QuizAttempt.objects.filter(student=self.student, quiz=self.quiz).exists())

        # Second load (refresh / F5) redirects to verify_quiz_pin
        refresh_load = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertRedirects(refresh_load, reverse('verify_quiz_pin', args=[self.quiz.id]))

    def test_attempt_resumes_safely_preserving_timer_and_answers(self):
        """Re-verifying PIN resumes the existing attempt, preserving saved answers and remaining deadline."""
        self.client.force_login(self.student)
        self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'PLANT7'})

        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        initial_deadline = attempt.deadline
        attempt.saved_answers[str(self.q1.id)] = 'True'
        attempt.locked_question_ids.append(str(self.q1.id))
        attempt.save()

        # Re-verify PIN to resume
        resume_res = self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'PLANT7'})
        self.assertRedirects(resume_res, reverse('take_quiz', args=[self.quiz.id]))

        # Check attempt state preserved
        resumed_attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(resumed_attempt.deadline, initial_deadline)
        self.assertEqual(resumed_attempt.saved_answers.get(str(self.q1.id)), 'True')
        self.assertIn(str(self.q1.id), resumed_attempt.locked_question_ids)

    def test_server_side_timeout_auto_submits(self):
        """When timer reaches zero, server automatically grades available answers and submits."""
        self.client.force_login(self.student)
        self.client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'PLANT7'})

        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        attempt.saved_answers = {str(self.q1.id): 'True', str(self.q2.id): 'Mandrake'}
        attempt.deadline = timezone.now() - timedelta(seconds=5)  # Expired timer
        attempt.save()

        # Attempt to access take_quiz with expired timer
        session = self.client.session
        session[f'pin_verified_quiz_{self.quiz.id}'] = True
        session.save()

        response = self.client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertTrue(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).exists())
        sub = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(sub.score, 2.0)
        self.assertRedirects(response, reverse('quiz_result', args=[sub.id]))


class QuizManagementAndResultsReleaseTests(TestCase):
    """
    Tests for Part 6, 7 & 8: Passing grade, quiz activation/deactivation,
    results release gating, and CSV export.
    """
    def setUp(self):
        self.instructor = User.objects.create_user(username='prof_vector', email='vector@hogwarts.edu', password='Pass')
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)

        self.student = User.objects.create_user(username='stu_anthony', email='anthony@hogwarts.edu', password='Pass')
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)
        StudentProfile.objects.create(user=self.student, full_name='Anthony Goldstein', student_id='STU-AG01')

        self.quiz = Quiz.objects.create(
            title='Arithmancy Exam',
            access_pin='NUM777',
            time_limit_minutes=20,
            deadline=timezone.now() + timedelta(hours=5),
            passing_percentage=70.0,
            is_active=True,
            results_released=False,
            created_by=self.instructor
        )
        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Is 7 a prime number?',
            question_type='TF',
            option_a='True',
            option_b='False',
            correct_answer='True'
        )

    def test_passing_percentage_configuration_and_pass_fail_determination(self):
        """Pass/fail determination respects quiz.passing_percentage."""
        sub = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers={'1': 'True'},
            signature_version=2,
            dsa_signature='sig'
        )
        self.assertTrue(sub.is_passed)

        # If score was 60% with passing_percentage 70%
        sub.percentage = 60.0
        sub.save()
        self.assertFalse(sub.is_passed)

    def test_inactive_quiz_inaccessible_to_students(self):
        """Students cannot verify PIN or take an inactive quiz."""
        self.quiz.is_active = False
        self.quiz.save()

        self.client.force_login(self.student)
        response = self.client.get(reverse('verify_quiz_pin', args=[self.quiz.id]))
        self.assertRedirects(response, reverse('student_dashboard'))

    def test_instructor_can_toggle_quiz_activation(self):
        """Instructor can toggle active/inactive status."""
        self.client.force_login(self.instructor)
        self.assertTrue(self.quiz.is_active)

        res = self.client.post(reverse('toggle_quiz_status', args=[self.quiz.id]))
        self.assertRedirects(res, reverse('instructor_dashboard'))
        self.quiz.refresh_from_db()
        self.assertFalse(self.quiz.is_active)

    def test_results_release_gating_protects_scores_and_answers(self):
        """Before release, students cannot see scores or correct answers. After release, reviews are revealed."""
        sub = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers={str(self.q1.id): 'True'},
            signature_version=2,
            dsa_signature='sig'
        )
        self.client.force_login(self.student)

        # Before release
        res_before = self.client.get(reverse('quiz_result', args=[sub.id]))
        self.assertEqual(res_before.status_code, 200)
        self.assertContains(res_before, 'Release Status: Pending Instructor Approval')
        self.assertNotContains(res_before, 'Detailed Question Review')

        # Release results
        self.quiz.results_released = True
        self.quiz.save()

        # After release
        res_after = self.client.get(reverse('quiz_result', args=[sub.id]))
        self.assertEqual(res_after.status_code, 200)
        self.assertContains(res_after, '100%')
        self.assertContains(res_after, 'Detailed Question Review')
        self.assertContains(res_after, 'PASSED')

    def test_csv_export_format_and_authorization(self):
        """Instructor who owns quiz can export results with UTF-8 BOM, student IDs, and verification status."""
        sub = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=1.0,
            percentage=100.0,
            answers={str(self.q1.id): 'True'},
            signature_version=2,
            dsa_signature='sig'
        )
        self.client.force_login(self.instructor)
        res = self.client.get(reverse('export_quiz_results', args=[self.quiz.id]))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'text/csv; charset=utf-8')
        content = res.content.decode('utf-8')
        self.assertTrue(content.startswith('\ufeff'))  # UTF-8 BOM
        self.assertIn('Anthony Goldstein', content)
        self.assertIn('STU-AG01', content)
        self.assertIn('PASSED', content)


class AuditAndSecurityTests(TestCase):
    """
    Tests for Part 10, 11 & 12: Audit trail logging, instructor security logs access,
    and cryptographic key management safety.
    """
    def setUp(self):
        self.instructor = User.objects.create_user(username='prof_sinistra', email='sinistra@hogwarts.edu', password='Pass')
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)

        self.student = User.objects.create_user(username='stu_dean', email='dean@hogwarts.edu', password='Pass')
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

    def test_student_denied_access_to_security_logs(self):
        """Ordinary students are denied access to security logs with HTTP 403."""
        self.client.force_login(self.student)
        res = self.client.get(reverse('security_logs'))
        self.assertEqual(res.status_code, 403)

    def test_instructor_can_view_security_logs(self):
        """Instructors can view centralized audit logs."""
        AuditLog.objects.create(
            actor=self.instructor,
            actor_username='prof_sinistra',
            action='LOGIN_SUCCESS',
            status='SUCCESS',
            details='Test audit entry'
        )
        self.client.force_login(self.instructor)
        res = self.client.get(reverse('security_logs'))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'LOGIN_SUCCESS')
        self.assertContains(res, 'prof_sinistra')

    def test_corrupted_key_raises_key_management_error_preventing_silent_replacement(self):
        """A corrupted private key raises KeyManagementError rather than silently replacing it."""
        import os
        import tempfile
        from pathlib import Path
        from quiz import crypto

        orig_path = crypto.PRIVATE_KEY_PATH
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"CORRUPTED_KEY_DATA")
            tf_path = Path(tf.name)

        try:
            crypto.PRIVATE_KEY_PATH = tf_path
            with self.assertRaises(KeyManagementError):
                crypto.get_dsa_private_key()
        finally:
            crypto.PRIVATE_KEY_PATH = orig_path
            if os.path.exists(tf_path):
                os.remove(tf_path)
