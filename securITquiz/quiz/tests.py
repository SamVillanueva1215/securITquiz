import json
from datetime import timedelta
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.urls import reverse

from quiz.models import StudentProfile, InstructorProfile, Quiz, Question, QuizSubmission
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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Bob Instructor',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Carol Instructor',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Severus Snape',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor_a,
            full_name='Instructor A',
            status='APPROVED'
        )

        # Instructor B (non-owner)
        self.instructor_b = User(username='instructor_b', email='b@uni.edu')
        self.instructor_b.set_unusable_password()
        self.instructor_b.save()
        self.instructor_b.groups.add(self.instructor_group)
        InstructorProfile.objects.create(
            user=self.instructor_b,
            full_name='Instructor B',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor_owner,
            full_name='Minerva McGonagall',
            status='APPROVED'
        )

        self.instructor_other = User(username='prof_flitwick', email='filius@hogwarts.edu')
        self.instructor_other.set_unusable_password()
        self.instructor_other.save()
        self.instructor_other.groups.add(self.instructor_group)
        InstructorProfile.objects.create(
            user=self.instructor_other,
            full_name='Filius Flitwick',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Filius Flitwick',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Pomona Sprout',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Septima Vector',
            status='APPROVED'
        )

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
from quiz.models import ActiveSession, QuizAttempt, AuditLog, SecurityLog, DeviceAuthorizationRequest
from quiz.crypto import KeyManagementError, get_dsa_private_key


class SingleActiveSessionTests(TestCase):
    """
    Tests for Part 2 & Requirement 3: Mutual Two-Device Authorization & Single Active Session Protection.
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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Filius Flitwick',
            status='APPROVED'
        )

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

    def test_second_device_login_rejected_while_first_remains_active(self):
        """Second Student login is rejected while first session remains authenticated and untouched."""
        client1 = Client()
        res1 = client1.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertRedirects(res1, reverse('student_dashboard'))
        original_key = ActiveSession.objects.get(user=self.student).session_key

        client2 = Client()
        res2 = client2.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertEqual(res2.status_code, 200)
        self.assertTemplateUsed(res2, 'quiz/login.html')
        self.assertContains(res2, 'already has an active session')

        dash2 = client2.get(reverse('student_dashboard'))
        self.assertRedirects(dash2, f"{reverse('login')}?next={reverse('student_dashboard')}")

        dash1 = client1.get(reverse('student_dashboard'))
        self.assertEqual(dash1.status_code, 200)
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, original_key)

    def test_student_can_login_on_second_device_after_post_logout(self):
        """After Device 1 logs out via POST, Device 2 can log in normally."""
        client1 = Client()
        client1.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertEqual(client1.get(reverse('student_dashboard')).status_code, 200)

        logout_res = client1.post(reverse('logout'))
        self.assertRedirects(logout_res, reverse('login'))
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

        client2 = Client()
        res2 = client2.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertRedirects(res2, reverse('student_dashboard'))
        self.assertEqual(client2.get(reverse('student_dashboard')).status_code, 200)

    def test_revoked_session_cannot_access_protected_routes(self):
        """Non-matching Student session keys are logged out cleanly by middleware."""
        client_a = Client()
        client_a.post(reverse('login'), {'username': 'student_alice', 'password': self.password})

        ActiveSession.objects.filter(user=self.student).update(session_key='different_key')

        res = client_a.get(reverse('student_dashboard'))
        self.assertRedirects(res, reverse('login'))

    def test_logout_requires_post_and_releases_active_session(self):
        """GET logout does not mutate state; POST logout releases matching ActiveSession record."""
        self.client.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertTrue(ActiveSession.objects.filter(user=self.student).exists())

        get_res = self.client.get(reverse('logout'))
        self.assertEqual(get_res.status_code, 405)
        self.assertTrue(ActiveSession.objects.filter(user=self.student).exists())
        self.assertEqual(self.client.get(reverse('student_dashboard')).status_code, 200)

        post_res = self.client.post(reverse('logout'))
        self.assertRedirects(post_res, reverse('login'))
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

    def test_inactivity_expiration_after_configured_timeout(self):
        """Middleware respects default 30-minute SESSION_INACTIVITY_TIMEOUT and logs SESSION_EXPIRED."""
        self.client.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        active = ActiveSession.objects.get(user=self.student)

        # 10 minutes of inactivity is within the 30-minute default window
        active.last_activity = timezone.now() - timedelta(minutes=10)
        active.save()
        still_active_res = self.client.get(reverse('student_dashboard'))
        self.assertEqual(still_active_res.status_code, 200)

        # Simulate 31 minutes of inactivity (> 30 minutes)
        active.refresh_from_db()
        active.last_activity = timezone.now() - timedelta(minutes=31)
        active.save()

        # Access an authenticated view -> expired & logged out
        response = self.client.get(reverse('student_dashboard'))
        self.assertRedirects(response, reverse('login'))
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

        # Verify SESSION_EXPIRED recorded in both AuditLog and SecurityLog
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_EXPIRED').exists())
        self.assertTrue(SecurityLog.objects.filter(username_attempted=self.student.username, action='SESSION_EXPIRED').exists())

    def test_stale_active_session_cleanup_at_login(self):
        """Stale/expired ActiveSession records (> 30 min) do not block legitimate logins and create SESSION_EXPIRED audit log."""
        ActiveSession.objects.create(
            user=self.student,
            session_key='stale_key_123',
            ip_address='192.168.1.50',
            last_activity=timezone.now() - timedelta(minutes=35)
        )

        client = Client()
        res = client.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertRedirects(res, reverse('student_dashboard'))

        # Successfully logged in with new active session
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, client.session.session_key)

        # SESSION_EXPIRED was recorded for the stale session
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_EXPIRED').exists())

    def test_independent_accounts_active_simultaneously(self):
        """Different Student accounts and Instructors can maintain independent active sessions simultaneously."""
        student_bob = User.objects.create_user(
            username='student_bob',
            email='bob_stu@hogwarts.edu',
            password=self.password
        )
        student_group, _ = Group.objects.get_or_create(name='Student')
        student_bob.groups.add(student_group)

        client_student = Client()
        res_s = client_student.post(reverse('login'), {'username': 'student_alice', 'password': self.password})
        self.assertRedirects(res_s, reverse('student_dashboard'))

        client_bob = Client()
        res_b = client_bob.post(reverse('login'), {'username': 'student_bob', 'password': self.password})
        self.assertRedirects(res_b, reverse('student_dashboard'))

        client_inst = Client()
        res_i = client_inst.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})
        self.assertRedirects(res_i, reverse('instructor_dashboard'))

        self.assertEqual(ActiveSession.objects.count(), 2)
        self.assertEqual(client_student.get(reverse('student_dashboard')).status_code, 200)
        self.assertEqual(client_bob.get(reverse('student_dashboard')).status_code, 200)
        self.assertEqual(client_inst.get(reverse('instructor_dashboard')).status_code, 200)

    def test_instructor_not_blocked_by_student_single_session_restriction(self):
        """Instructors can hold concurrent sessions across multiple clients without blocking."""
        client1 = Client()
        res1 = client1.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})
        self.assertRedirects(res1, reverse('instructor_dashboard'))

        client2 = Client()
        res2 = client2.post(reverse('login'), {'username': 'prof_flitwick', 'password': self.password})
        self.assertRedirects(res2, reverse('instructor_dashboard'))

        self.assertEqual(client1.get(reverse('instructor_dashboard')).status_code, 200)
        self.assertEqual(client2.get(reverse('instructor_dashboard')).status_code, 200)


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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Pomona Sprout',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Septima Vector',
            status='APPROVED'
        )

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
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Aurora Sinistra',
            status='APPROVED'
        )

        self.student = User.objects.create_user(username='stu_dean', email='dean@hogwarts.edu', password='Pass')
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

        self.admin_user = User.objects.create_user(username='admin_albus', email='albus@hogwarts.edu', password='Pass')
        admin_group, _ = Group.objects.get_or_create(name='Administrator')
        self.admin_user.groups.add(admin_group)

    def test_student_denied_access_to_security_logs(self):
        """Ordinary students are denied access to security logs with HTTP 403."""
        self.client.force_login(self.student)
        res = self.client.get(reverse('security_logs'))
        self.assertEqual(res.status_code, 403)

    def test_ordinary_instructor_denied_from_security_logs(self):
        """Ordinary instructors (even if approved) are denied access to security logs with HTTP 403."""
        self.client.force_login(self.instructor)
        res = self.client.get(reverse('security_logs'))
        self.assertEqual(res.status_code, 403)

    def test_administrator_can_view_security_logs(self):
        """Administrators can view centralized system security and audit logs."""
        AuditLog.objects.create(
            actor=self.instructor,
            actor_username='prof_sinistra',
            action='LOGIN_SUCCESS',
            status='SUCCESS',
            details='Test audit entry'
        )
        self.client.force_login(self.admin_user)
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


class ComprehensiveAuditAndSessionLifecycleTests(TestCase):
    """
    Tests for complete audit logging coverage (Part 4.4), server-issued device identification (Part 3.6),
    and edge-case session management.
    """
    def setUp(self):
        self.password = 'P@ssw0rd123!'
        self.student = User.objects.create_user(
            username='audit_student',
            email='audit@student.edu',
            password=self.password
        )
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

    def test_session_created_and_logout_audit_logging(self):
        """Verifies SESSION_CREATED and SESSION_LOGOUT audit events are recorded."""
        client = Client()
        # Login records SESSION_CREATED and LOGIN_SUCCESS
        res = client.post(reverse('login'), {'username': 'audit_student', 'password': self.password})
        self.assertRedirects(res, reverse('student_dashboard'))
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_CREATED').exists())
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='LOGIN_SUCCESS').exists())

        # Logout via POST records SESSION_LOGOUT and LOGOUT
        res_logout = client.post(reverse('logout'))
        self.assertRedirects(res_logout, reverse('login'))
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_LOGOUT').exists())
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='LOGOUT').exists())

    def test_session_revoked_audit_logging_on_superseded_device(self):
        """Verifies SESSION_REVOKED is recorded when a session key does not match ActiveSession."""
        client_a = Client()
        client_a.post(reverse('login'), {'username': 'audit_student', 'password': self.password})
        self.assertTrue(ActiveSession.objects.filter(user=self.student).exists())

        ActiveSession.objects.filter(user=self.student).update(session_key='superseded_key')

        res = client_a.get(reverse('student_dashboard'))
        self.assertRedirects(res, reverse('login'))
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_REVOKED').exists())
        self.assertTrue(SecurityLog.objects.filter(username_attempted='audit_student', action='SESSION_REVOKED').exists())

    def test_rejected_concurrent_student_login_audit_events(self):
        """
        Verifies CONCURRENT_LOGIN_BLOCKED audit log and BLOCKED_CONCURRENT_LOGIN security log
        when a Student attempts a duplicate login while an active session exists.
        """
        client_a = Client()
        client_a.post(reverse('login'), {'username': 'audit_student', 'password': self.password})

        client_b = Client()
        res_b = client_b.post(reverse('login'), {'username': 'audit_student', 'password': self.password})
        self.assertEqual(res_b.status_code, 200)
        self.assertContains(res_b, 'already has an active session')

        self.assertTrue(
            AuditLog.objects.filter(actor=self.student, action='CONCURRENT_LOGIN_BLOCKED', status='BLOCKED').exists()
        )
        self.assertTrue(
            SecurityLog.objects.filter(username_attempted='audit_student', action='BLOCKED_CONCURRENT_LOGIN', is_success=False).exists()
        )

    def test_server_issued_device_id_cookie_and_storage(self):
        """Verifies server issues secure securit_device_id cookie and associates it with ActiveSession."""
        client = Client()
        res = client.get(reverse('login'))
        self.assertEqual(res.status_code, 200)

        # Cookie securit_device_id was set
        self.assertIn('securit_device_id', res.cookies)
        device_id = res.cookies['securit_device_id'].value
        self.assertTrue(len(device_id) > 10)

        # On login, device_id is recorded in ActiveSession
        client.post(reverse('login'), {'username': 'audit_student', 'password': self.password})
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.device_id, device_id)


class NotificationIntegrationTests(TestCase):
    """
    Tests for Part 6: Email and Notification Integration across all 9 required scenarios.
    """
    def setUp(self):
        from django.core import mail
        mail.outbox.clear()

        self.instructor = User.objects.create_user(
            username='prof_vector',
            email='vector@hogwarts.edu',
            password='Pass'
        )
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)

        self.student = User.objects.create_user(
            username='stu_colin',
            email='colin@hogwarts.edu',
            password='Pass'
        )
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)

        self.quiz = Quiz.objects.create(
            title='Arithmancy Midterm',
            access_pin='ARITH1',
            deadline=timezone.now() + timedelta(days=1),
            created_by=self.instructor
        )

    def test_all_9_notification_scenarios(self):
        """Verifies that all 9 notification scenarios format and dispatch emails correctly."""
        from django.core import mail
        from quiz import notifications

        # Scenario 1: Suspicious login / security event
        ok1 = notifications.notify_suspicious_security_event(
            user=self.student,
            ip_address='198.51.100.1',
            event_type='Unusual IP Login',
            details='Login from foreign network'
        )
        self.assertTrue(ok1)
        self.assertIn('Unusual IP Login', mail.outbox[-1].subject)
        self.assertEqual(mail.outbox[-1].to, ['colin@hogwarts.edu'])

        # Scenario 2: New device authorization request
        ok2 = notifications.notify_device_auth_requested(
            user=self.student,
            requesting_ip='198.51.100.2',
            expires_at=timezone.now() + timedelta(seconds=60)
        )
        self.assertTrue(ok2)
        self.assertIn('Authorization Request', mail.outbox[-1].subject)
        self.assertIn('198.51.100.2', mail.outbox[-1].body)

        # Scenario 3: Device authorization approved
        ok3 = notifications.notify_device_auth_approved(
            user=self.student,
            requesting_ip='198.51.100.2',
            approver_ip='198.51.100.1'
        )
        self.assertTrue(ok3)
        self.assertIn('Approved', mail.outbox[-1].subject)
        self.assertIn('198.51.100.2', mail.outbox[-1].body)

        # Scenario 4: Device authorization denied
        ok4 = notifications.notify_device_auth_denied(
            user=self.student,
            requesting_ip='198.51.100.2',
            denier_ip='198.51.100.1'
        )
        self.assertTrue(ok4)
        self.assertIn('Denied', mail.outbox[-1].subject)

        # Scenario 5: Device authorization expired
        ok5 = notifications.notify_device_auth_expired(
            user=self.student,
            requesting_ip='198.51.100.2'
        )
        self.assertTrue(ok5)
        self.assertIn('Timed Out', mail.outbox[-1].subject)

        # Create submission for scenarios 6, 7, 8
        sub = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=95.0,
            percentage=95.0,
            dsa_signature='sig123',
            signature_version=2
        )

        # Scenario 6: Student submission confirmation
        ok6 = notifications.notify_student_submission_confirmation(sub)
        self.assertTrue(ok6)
        self.assertIn('Submission Confirmation', mail.outbox[-1].subject)
        self.assertEqual(mail.outbox[-1].to, ['colin@hogwarts.edu'])

        # Scenario 7: Instructor new submission alert
        ok7 = notifications.notify_instructor_new_submission(sub)
        self.assertTrue(ok7)
        self.assertIn('New Submission Received', mail.outbox[-1].subject)
        self.assertEqual(mail.outbox[-1].to, ['vector@hogwarts.edu'])

        # Scenario 8: DSA verification failure alert
        ok8 = notifications.notify_instructor_dsa_failure(sub)
        self.assertTrue(ok8)
        self.assertIn('URGENT SECURITY ALERT: DSA', mail.outbox[-1].subject)
        self.assertEqual(mail.outbox[-1].to, ['vector@hogwarts.edu'])

        # Scenario 9: Quiz results released notification
        ok9 = notifications.notify_students_results_released(self.quiz)
        self.assertTrue(ok9)
        self.assertIn('Results Released', mail.outbox[-1].subject)
        self.assertEqual(mail.outbox[-1].to, ['colin@hogwarts.edu'])

        # All 9 scenarios triggered and sent emails safely
        self.assertEqual(len(mail.outbox), 9)


class LegacyUnsignedDsaStatusTests(TestCase):
    """
    Tests for Part 2.4: Accurate status classification for Unsigned/Legacy records vs Tampered vs Verified.
    """
    def setUp(self):
        self.instructor = User.objects.create_user(
            username='prof_bathsheda',
            email='bathsheda@hogwarts.edu',
            password='Pass'
        )
        instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.instructor.groups.add(instructor_group)
        InstructorProfile.objects.create(
            user=self.instructor,
            full_name='Bathsheda Babbling',
            status='APPROVED'
        )

        self.student = User.objects.create_user(
            username='stu_seamus',
            email='seamus@hogwarts.edu',
            password='Pass'
        )
        student_group, _ = Group.objects.get_or_create(name='Student')
        self.student.groups.add(student_group)
        StudentProfile.objects.create(
            user=self.student,
            full_name='Seamus Finnigan',
            student_id='STU-SF01'
        )

        self.quiz = Quiz.objects.create(
            title='Ancient Runes Quiz',
            access_pin='RUNES1',
            deadline=timezone.now() + timedelta(days=1),
            created_by=self.instructor
        )

    def test_legacy_unsigned_record_classified_as_unsigned(self):
        """A submission with empty dsa_signature is classified as Unsigned / Legacy, not Tampered."""
        sub = QuizSubmission.objects.create(
            student=self.student,
            quiz=self.quiz,
            score=50.0,
            percentage=50.0,
            dsa_signature="",
            signature_version=1
        )
        self.client.force_login(self.instructor)

        # Results table view
        res = self.client.get(reverse('instructor_quiz_results', args=[self.quiz.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'Unsigned / Legacy')
        self.assertNotContains(res, 'Compromised / Tampered')

        # Submission detail view
        res_detail = self.client.get(reverse('instructor_submission_detail', args=[sub.id]))
        self.assertEqual(res_detail.status_code, 200)
        self.assertContains(res_detail, 'Unsigned / Legacy Record (Missing Signature)')

        # CSV export
        res_csv = self.client.get(reverse('export_quiz_results', args=[self.quiz.id]))
        content = res_csv.content.decode('utf-8')
        self.assertIn('UNSIGNED / UNVERIFIED', content)


class InstructorAuthorizationAndStatusTests(TestCase):
    """
    Phase 2A Tests: Instructor Access Control based on InstructorProfile status.
    - APPROVED instructors can access instructor views.
    - PENDING instructors are denied access with HTTP 403.
    - REJECTED instructors are denied access with HTTP 403.
    - Missing InstructorProfile records are handled safely and denied with HTTP 403.
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        # Approved Instructor
        self.approved_user = User.objects.create_user(
            username='prof_approved', email='approved@uni.edu', password='Pass'
        )
        self.approved_user.groups.add(self.instructor_group)
        self.approved_profile = InstructorProfile.objects.create(
            user=self.approved_user, full_name='Prof Approved', status='APPROVED'
        )

        # Pending Instructor
        self.pending_user = User.objects.create_user(
            username='prof_pending', email='pending@uni.edu', password='Pass'
        )
        self.pending_user.groups.add(self.instructor_group)
        self.pending_profile = InstructorProfile.objects.create(
            user=self.pending_user, full_name='Prof Pending', status='PENDING'
        )

        # Rejected Instructor
        self.rejected_user = User.objects.create_user(
            username='prof_rejected', email='rejected@uni.edu', password='Pass'
        )
        self.rejected_user.groups.add(self.instructor_group)
        self.rejected_profile = InstructorProfile.objects.create(
            user=self.rejected_user,
            full_name='Prof Rejected',
            status='REJECTED',
            rejection_reason='Incomplete academic credentials'
        )

        # Missing Profile Instructor
        self.missing_profile_user = User.objects.create_user(
            username='prof_noprofile', email='noprofile@uni.edu', password='Pass'
        )
        self.missing_profile_user.groups.add(self.instructor_group)

        # Sample Quiz owned by approved instructor
        self.quiz = Quiz.objects.create(
            title='Sample Quiz',
            deadline=timezone.now() + timedelta(days=1),
            access_pin='TEST12',
            created_by=self.approved_user
        )

    def test_approved_instructor_can_access_dashboard(self):
        self.client.force_login(self.approved_user)
        res = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(res.status_code, 200)

    def test_pending_instructor_denied_from_dashboard(self):
        self.client.force_login(self.pending_user)
        res = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(res.status_code, 403)
        self.assertContains(res, 'Access Denied', status_code=403)
        self.assertContains(res, 'Pending Approval', status_code=403)

    def test_rejected_instructor_denied_from_dashboard(self):
        self.client.force_login(self.rejected_user)
        res = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(res.status_code, 403)
        self.assertContains(res, 'Access Denied', status_code=403)
        self.assertContains(res, 'Incomplete academic credentials', status_code=403)

    def test_missing_profile_instructor_denied_from_dashboard(self):
        self.client.force_login(self.missing_profile_user)
        res = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(res.status_code, 403)
        self.assertContains(res, 'Access Denied', status_code=403)
        self.assertContains(res, 'profile not found', status_code=403)

    def test_pending_instructor_denied_from_create_quiz(self):
        self.client.force_login(self.pending_user)
        res = self.client.get(reverse('create_quiz'))
        self.assertEqual(res.status_code, 403)

    def test_rejected_instructor_denied_from_create_quiz(self):
        self.client.force_login(self.rejected_user)
        res = self.client.get(reverse('create_quiz'))
        self.assertEqual(res.status_code, 403)

    def test_missing_profile_denied_from_create_quiz(self):
        self.client.force_login(self.missing_profile_user)
        res = self.client.get(reverse('create_quiz'))
        self.assertEqual(res.status_code, 403)

    def test_pending_instructor_denied_from_edit_quiz(self):
        self.client.force_login(self.pending_user)
        res = self.client.get(reverse('edit_quiz', kwargs={'quiz_id': self.quiz.id}))
        self.assertEqual(res.status_code, 403)

    def test_pending_instructor_denied_from_results(self):
        self.client.force_login(self.pending_user)
        res = self.client.get(reverse('instructor_quiz_results', kwargs={'quiz_id': self.quiz.id}))
        self.assertEqual(res.status_code, 403)

    def test_pending_instructor_denied_from_export(self):
        self.client.force_login(self.pending_user)
        res = self.client.get(reverse('export_quiz_results', kwargs={'quiz_id': self.quiz.id}))
        self.assertEqual(res.status_code, 403)

    def test_pending_instructor_denied_from_toggle_status(self):
        self.client.force_login(self.pending_user)
        res = self.client.post(reverse('toggle_quiz_status', kwargs={'quiz_id': self.quiz.id}))
        self.assertEqual(res.status_code, 403)

    def test_pending_instructor_denied_from_toggle_results(self):
        self.client.force_login(self.pending_user)
        res = self.client.post(reverse('toggle_quiz_results', kwargs={'quiz_id': self.quiz.id}))
        self.assertEqual(res.status_code, 403)


class InstructorRegistrationUnitAndIntegrationTests(TestCase):
    """
    Phase 2A Tests: Public Instructor Registration & Administrator Guardrails.
    - Public registration creates User + InstructorProfile with PENDING status.
    - Assigns Instructor group membership.
    - Logs INSTRUCTOR_REGISTERED audit event.
    - Blocks public Administrator registration attempts.
    - Preserves existing Student registration.
    """
    def setUp(self):
        self.client = Client()
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

    def test_public_instructor_registration_success(self):
        res = self.client.post(reverse('register_instructor'), {
            'full_name': 'Dr. Alan Turing',
            'department': 'Computer Science',
            'email': 'turing@cambridge.edu',
            'username': 'alan_turing',
            'password1': 'BletchleyPark1945!',
            'password2': 'BletchleyPark1945!',
        })
        self.assertRedirects(res, reverse('login'))

        user = User.objects.get(username='alan_turing')
        self.assertEqual(user.email, 'turing@cambridge.edu')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.groups.filter(name='Instructor').exists())
        self.assertFalse(user.groups.filter(name='Administrator').exists())

        profile = user.instructor_profile
        self.assertEqual(profile.status, 'PENDING')
        self.assertEqual(profile.full_name, 'Dr. Alan Turing')
        self.assertEqual(profile.department, 'Computer Science')
        self.assertFalse(profile.is_authorized())

        log = AuditLog.objects.filter(actor=user, action='INSTRUCTOR_REGISTERED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.status, 'PENDING')

    def test_newly_registered_instructor_denied_access_until_approved(self):
        self.client.post(reverse('register_instructor'), {
            'full_name': 'Dr. Ada Lovelace',
            'department': 'Mathematics',
            'email': 'ada@oxford.edu',
            'username': 'ada_lovelace',
            'password1': 'AnalyticalEngine1843!',
            'password2': 'AnalyticalEngine1843!',
        })
        user = User.objects.get(username='ada_lovelace')
        self.client.force_login(user)
        res = self.client.get(reverse('instructor_dashboard'))
        self.assertEqual(res.status_code, 403)

    def test_public_registration_blocks_administrator_attempts(self):
        res1 = self.client.get(reverse('register'), {'role': 'administrator'})
        self.assertEqual(res1.status_code, 403)
        self.assertContains(res1, 'Public Administrator registration is strictly prohibited.', status_code=403)

        res2 = self.client.get(reverse('register_instructor'), {'role': 'admin'})
        self.assertEqual(res2.status_code, 403)
        self.assertContains(res2, 'Public Administrator registration is strictly prohibited.', status_code=403)

    def test_existing_student_registration_preserved(self):
        res = self.client.post(reverse('register'), {
            'full_name': 'Grace Hopper',
            'student_id': 'STU99001',
            'email': 'hopper@navy.mil',
            'username': 'grace_hopper',
            'password1': 'CobolCompiler1959!',
            'password2': 'CobolCompiler1959!',
        })
        self.assertRedirects(res, reverse('login'))
        user = User.objects.get(username='grace_hopper')
        self.assertTrue(user.groups.filter(name='Student').exists())
        self.assertEqual(user.student_profile.student_id, 'STU99001')


class InstructorApprovalFoundationTests(TestCase):
    """
    Phase 2A Tests: InstructorProfile approval & rejection lifecycle.
    - Recording reviewer, timestamp, and rejection reason.
    - Preventing unauthorized users from approving or rejecting instructors.
    """
    def setUp(self):
        self.admin_group, _ = Group.objects.get_or_create(name='Administrator')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.student_group, _ = Group.objects.get_or_create(name='Student')

        self.admin_user = User.objects.create_user(
            username='admin_user', email='admin@uni.edu', password='Pass'
        )
        self.admin_user.groups.add(self.admin_group)

        self.ordinary_instructor = User.objects.create_user(
            username='prof_ordinary', email='ordinary@uni.edu', password='Pass'
        )
        self.ordinary_instructor.groups.add(self.instructor_group)

        self.student_user = User.objects.create_user(
            username='student_user', email='student@uni.edu', password='Pass'
        )
        self.student_user.groups.add(self.student_group)

        self.applicant = User.objects.create_user(
            username='applicant_jane', email='jane@uni.edu', password='Pass'
        )
        self.applicant.groups.add(self.instructor_group)
        self.profile = InstructorProfile.objects.create(
            user=self.applicant, full_name='Jane Applicant', status='PENDING'
        )

    def test_administrator_can_approve_instructor(self):
        self.profile.approve(self.admin_user)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, 'APPROVED')
        self.assertEqual(self.profile.reviewed_by, self.admin_user)
        self.assertIsNotNone(self.profile.reviewed_at)
        self.assertEqual(self.profile.rejection_reason, '')
        self.assertTrue(self.profile.is_authorized())

        log = AuditLog.objects.filter(actor=self.admin_user, action='INSTRUCTOR_APPROVED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.status, 'APPROVED')

    def test_administrator_can_reject_instructor_with_reason(self):
        self.profile.reject(self.admin_user, reason='Department verification failed')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, 'REJECTED')
        self.assertEqual(self.profile.reviewed_by, self.admin_user)
        self.assertIsNotNone(self.profile.reviewed_at)
        self.assertEqual(self.profile.rejection_reason, 'Department verification failed')
        self.assertFalse(self.profile.is_authorized())

        log = AuditLog.objects.filter(actor=self.admin_user, action='INSTRUCTOR_REJECTED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.status, 'REJECTED')

    def test_approval_clears_previous_rejection_reason(self):
        self.profile.reject(self.admin_user, reason='Missing transcript')
        self.profile.approve(self.admin_user)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, 'APPROVED')
        self.assertEqual(self.profile.rejection_reason, '')

    def test_unauthorized_user_cannot_approve_instructor(self):
        with self.assertRaises(PermissionError):
            self.profile.approve(self.ordinary_instructor)
        with self.assertRaises(PermissionError):
            self.profile.approve(self.student_user)
        with self.assertRaises(PermissionError):
            self.profile.approve(None)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, 'PENDING')

    def test_unauthorized_user_cannot_reject_instructor(self):
        with self.assertRaises(PermissionError):
            self.profile.reject(self.ordinary_instructor, reason='Unauthorized attempt')
        with self.assertRaises(PermissionError):
            self.profile.reject(self.student_user, reason='Student attempt')

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, 'PENDING')


class AdminBootstrapTests(TestCase):
    """
    Phase 2B Tests: Secure Administrator Bootstrap via `create_admin` management command.
    Verifies group creation, least-privilege flags, getpass usage, password validation,
    duplicate/conflict protection, audit logging, atomic rollback, and login routing.
    """
    def setUp(self):
        self.client = Client()

    def test_successful_admin_creation_via_prompts(self):
        """Bootstraps initial Administrator, auto-creates Administrator group, hashes with Argon2, and logs audit event."""
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command

        secret_pw = 'V3ryStr0ng!AdminPass#2026'
        out = StringIO()
        err = StringIO()

        with patch('builtins.input', side_effect=['sys_admin', 'sysadmin@university.edu']), \
             patch('getpass.getpass', side_effect=[secret_pw, secret_pw]):
            call_command('create_admin', stdout=out, stderr=err)

        stdout_text = out.getvalue()
        stderr_text = err.getvalue()

        # Verify user created with expected least-privilege flags
        admin_user = User.objects.get(username='sys_admin')
        self.assertEqual(admin_user.email, 'sysadmin@university.edu')
        self.assertTrue(admin_user.is_staff)
        self.assertFalse(admin_user.is_superuser)
        self.assertTrue(admin_user.is_active)
        self.assertTrue(admin_user.password.startswith('argon2'))
        self.assertTrue(admin_user.check_password(secret_pw))

        # Verify Administrator group created and assigned exclusively
        self.assertTrue(Group.objects.filter(name='Administrator').exists())
        self.assertTrue(admin_user.groups.filter(name='Administrator').exists())
        self.assertFalse(admin_user.groups.filter(name='Instructor').exists())
        self.assertFalse(admin_user.groups.filter(name='Student').exists())

        # Verify scoped Django Admin permissions assigned to Administrator group
        admin_group = Group.objects.get(name='Administrator')
        perm_codenames = set(admin_group.permissions.values_list('codename', flat=True))
        self.assertIn('view_instructorprofile', perm_codenames)
        self.assertIn('change_instructorprofile', perm_codenames)
        self.assertIn('view_auditlog', perm_codenames)

        # Verify password is NEVER printed in command output
        self.assertNotIn(secret_pw, stdout_text)
        self.assertNotIn(secret_pw, stderr_text)
        self.assertIn('Successfully created initial Administrator', stdout_text)

        # Verify ADMIN_CREATED audit log exists and contains no credentials
        log = AuditLog.objects.filter(actor=admin_user, action='ADMIN_CREATED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.status, 'SUCCESS')
        self.assertNotIn(secret_pw, log.details)
        self.assertNotIn(admin_user.password, log.details)

        # Verify bootstrapped Administrator can log in via /login/ and view security logs
        res = self.client.post(reverse('login'), {
            'username': 'sys_admin',
            'password': secret_pw,
        })
        self.assertRedirects(res, reverse('security_logs'))

    def test_password_confirmation_mismatch_rejected(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        with patch('builtins.input', side_effect=['sys_admin', 'sysadmin@university.edu']), \
             patch('getpass.getpass', side_effect=['StrongPass!2026', 'DifferentPass!2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('do not match', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='sys_admin').exists())
        self.assertFalse(AuditLog.objects.filter(action='ADMIN_CREATED').exists())

    def test_invalid_password_rejected_by_validators(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        with patch('builtins.input', side_effect=['sys_admin', 'sysadmin@university.edu']), \
             patch('getpass.getpass', side_effect=['1234', '1234']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('Password validation failed', str(ctx.exception))
        self.assertNotIn('1234', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='sys_admin').exists())

    def test_duplicate_username_rejected(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        User.objects.create_user(username='existing_user', email='other@uni.edu', password='Pass')

        with patch('builtins.input', side_effect=['EXISTING_USER', 'new@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('already exists', str(ctx.exception))

    def test_duplicate_email_rejected(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        User.objects.create_user(username='existing_user', email='dup@university.edu', password='Pass')

        with patch('builtins.input', side_effect=['new_admin', 'DUP@university.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('already exists', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='new_admin').exists())

    def test_invalid_email_format_rejected(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        with patch('builtins.input', side_effect=['new_admin', 'not-an-email']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('Invalid email', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='new_admin').exists())

    def test_prevents_duplicate_initial_administrator(self):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        admin_group, _ = Group.objects.get_or_create(name='Administrator')
        first_admin = User.objects.create_user(username='first_admin', email='first@uni.edu', password='Pass')
        first_admin.groups.add(admin_group)

        with patch('builtins.input', side_effect=['second_admin', 'second@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('already exists', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='second_admin').exists())

    def test_failed_creation_rolls_back_atomically(self):
        """If audit logging fails inside transaction, no partial User or Group membership persists."""
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command

        with patch('builtins.input', side_effect=['atomic_admin', 'atomic@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']), \
             patch('quiz.management.commands.create_admin.AuditLog.objects.create', side_effect=RuntimeError('DB failure')):
            with self.assertRaises(RuntimeError):
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertFalse(User.objects.filter(username='atomic_admin').exists())
        self.assertFalse(Group.objects.filter(name='Administrator').exists())

    def test_missing_required_permission_raises_command_error_and_rolls_back(self):
        """If any permission in ADMIN_SCOPED_PERMISSIONS is missing, raise CommandError and roll back."""
        from io import StringIO
        from unittest.mock import patch
        from django.contrib.auth.models import Permission
        from django.core.management import call_command, CommandError

        Permission.objects.filter(
            content_type__app_label='quiz',
            codename='change_instructorprofile'
        ).delete()

        with patch('builtins.input', side_effect=['perm_admin', 'permadmin@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('quiz.change_instructorprofile', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='perm_admin').exists())
        self.assertFalse(Group.objects.filter(name='Administrator').exists())
        self.assertFalse(AuditLog.objects.filter(action='ADMIN_CREATED').exists())

    def test_refuses_bootstrap_if_active_superuser_exists_without_admin_group(self):
        """Existing active superuser outside Administrator group blocks bootstrap without being modified."""
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command, CommandError

        legacy_super = User.objects.create_superuser(
            username='legacy_root',
            email='root@uni.edu',
            password='V3ryStr0ng!Root2026'
        )
        original_password_hash = legacy_super.password

        with patch('builtins.input', side_effect=['new_admin', 'newadmin@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('manual review', str(ctx.exception).lower())
        self.assertFalse(User.objects.filter(username='new_admin').exists())
        self.assertFalse(Group.objects.filter(name='Administrator').exists())

        # Existing superuser must remain completely unmodified
        legacy_super.refresh_from_db()
        self.assertEqual(legacy_super.password, original_password_hash)
        self.assertTrue(legacy_super.is_superuser)
        self.assertFalse(legacy_super.groups.filter(name='Administrator').exists())

    def test_concurrent_bootstrap_protection_acquires_postgres_advisory_lock_and_rechecks(self):
        """Verifies pg_advisory_xact_lock is requested on PostgreSQL and concurrent TOCTOU creation is blocked."""
        from io import StringIO
        from unittest.mock import MagicMock, patch
        from django.core.management import call_command, CommandError
        from quiz.management.commands.create_admin import Command as CreateAdminCommand

        # 1. Verify PostgreSQL advisory lock path is executed when vendor == 'postgresql'
        mock_cursor = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_cursor
        mock_cm.__exit__.return_value = False

        cmd = CreateAdminCommand()
        with patch('quiz.management.commands.create_admin.connection') as mock_conn:
            mock_conn.vendor = 'postgresql'
            mock_conn.cursor.return_value = mock_cm
            mock_conn.features.has_select_for_update = False
            cmd._acquire_bootstrap_lock()

        mock_cursor.execute.assert_called_once()
        sql_arg = mock_cursor.execute.call_args[0][0]
        self.assertIn('pg_advisory_xact_lock', sql_arg)

        # 2. Simulate concurrent process creating an Administrator right before atomic lock check
        def simulate_race_during_lock():
            admin_group, _ = Group.objects.get_or_create(name='Administrator')
            racer = User.objects.create_user(
                username='racer_admin', email='racer@uni.edu', password='Pass'
            )
            racer.groups.add(admin_group)

        with patch('builtins.input', side_effect=['second_racer', 'secondracer@uni.edu']), \
             patch('getpass.getpass', side_effect=['V3ryStr0ng!Pass2026', 'V3ryStr0ng!Pass2026']), \
             patch.object(CreateAdminCommand, '_acquire_bootstrap_lock', side_effect=simulate_race_during_lock):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('already exists', str(ctx.exception))
        self.assertFalse(User.objects.filter(username='second_racer').exists())

    def test_refuses_echoed_password_when_getpass_warns_or_stdin_not_tty(self):
        """Aborts cleanly if terminal echo cannot be suppressed or stdin is non-interactive."""
        import getpass
        import warnings
        from io import StringIO
        from unittest.mock import MagicMock, patch
        from django.core.management import call_command, CommandError

        # Case 1: getpass emits GetPassWarning (fallback_getpass echo condition)
        def warn_getpass(prompt='Password: '):
            warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
            return 'V3ryStr0ng!Pass2026'

        with patch('builtins.input', side_effect=['echo_admin', 'echoadmin@uni.edu']), \
             patch('getpass.getpass', side_effect=warn_getpass):
            with self.assertRaises(CommandError) as ctx:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('echo', str(ctx.exception).lower())
        self.assertFalse(User.objects.filter(username='echo_admin').exists())

        # Case 2: getpass points directly to fallback_getpass
        with patch('builtins.input', side_effect=['echo_admin2', 'echoadmin2@uni.edu']), \
             patch('getpass.getpass', getpass.fallback_getpass):
            with self.assertRaises(CommandError) as ctx2:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('echo', str(ctx2.exception).lower())
        self.assertFalse(User.objects.filter(username='echo_admin2').exists())

        # Case 3: Real getpass module function with non-TTY stdin
        fake_stdin = MagicMock()
        fake_stdin.isatty.return_value = False
        real_like_getpass = MagicMock(__module__='getpass')
        with patch('builtins.input', side_effect=['nontty_admin', 'nontty@uni.edu']), \
             patch('getpass.getpass', real_like_getpass), \
             patch('sys.stdin', fake_stdin):
            with self.assertRaises(CommandError) as ctx3:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('interactive terminal', str(ctx3.exception).lower())
        self.assertFalse(User.objects.filter(username='nontty_admin').exists())

        # Case 4: Unsupported / aborted terminal input (EOFError)
        with patch('builtins.input', side_effect=['eof_admin', 'eof@uni.edu']), \
             patch('getpass.getpass', side_effect=EOFError()):
            with self.assertRaises(CommandError) as ctx4:
                call_command('create_admin', stdout=StringIO(), stderr=StringIO())

        self.assertIn('aborted', str(ctx4.exception).lower())
        self.assertFalse(User.objects.filter(username='eof_admin').exists())


class PublicAdminRegistrationProtectionTests(TestCase):
    """
    Phase 2B Tests: Ensures manipulated POST requests cannot register Administrators
    while preserving Student and pending Instructor registration.
    """
    def setUp(self):
        self.client = Client()

    def test_manipulated_post_to_student_register_blocks_admin_fields(self):
        payloads = [
            {'role': 'Administrator'},
            {'group': 'Administrator'},
            {'groups': 'Administrator'},
            {'account_type': 'admin'},
            {'is_superuser': 'true'},
            {'is_staff': 'true'},
        ]
        for extra in payloads:
            data = {
                'full_name': 'Malicious Actor',
                'student_id': 'STU-HACK',
                'email': 'hacker@uni.edu',
                'username': 'hacker_admin',
                'password1': 'V3ryStr0ng!Pass2026',
                'password2': 'V3ryStr0ng!Pass2026',
            }
            data.update(extra)
            res = self.client.post(reverse('register'), data)
            self.assertEqual(res.status_code, 403)
            self.assertFalse(User.objects.filter(username='hacker_admin').exists())

    def test_manipulated_post_to_instructor_register_blocks_admin_fields(self):
        res = self.client.post(reverse('register_instructor'), {
            'full_name': 'Malicious Instructor',
            'department': 'Security',
            'email': 'hacker2@uni.edu',
            'username': 'hacker_inst',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
            'role': 'administrator',
            'is_superuser': 'on',
        })
        self.assertEqual(res.status_code, 403)
        self.assertFalse(User.objects.filter(username='hacker_inst').exists())


class Phase2CRegistrationSecurityTests(TestCase):
    """
    Phase 2C Tests (1-13): Strict registration restrictions, manipulated POST rejection,
    authenticated registration blocking, duplicate username/email prevention, and Phase 2A/2B preservation.
    """
    def setUp(self):
        self.client = Client()
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.admin_group, _ = Group.objects.get_or_create(name='Administrator')

        self.existing_student = User.objects.create_user(
            username='existing_stu',
            email='existing_stu@uni.edu',
            password='V3ryStr0ng!Pass2026'
        )
        self.existing_student.groups.add(self.student_group)

    def test_student_registration_assigns_only_student_role(self):
        res = self.client.post(reverse('register'), {
            'full_name': 'Alice Student',
            'student_id': 'STU-2C-01',
            'email': 'alice2c@uni.edu',
            'username': 'alice_2c',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
        })
        self.assertRedirects(res, reverse('login'))
        user = User.objects.get(username='alice_2c')
        self.assertEqual(list(user.groups.values_list('name', flat=True)), ['Student'])
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_student_registration_rejects_manipulated_role_and_flag_fields(self):
        manipulated_payloads = [
            {'role': 'Instructor'},
            {'role': 'Administrator'},
            {'group': 'Administrator'},
            {'groups': 'Instructor'},
            {'account_type': 'admin'},
            {'user_type': 'superuser'},
            {'is_staff': 'true'},
            {'is_superuser': 'true'},
            {'is_active': 'false'},
            {'permissions': 'quiz.view_auditlog'},
            {'user_permissions': '1'},
        ]
        for idx, extra in enumerate(manipulated_payloads):
            uname = f'manip_stu_{idx}'
            data = {
                'full_name': 'Manipulated User',
                'student_id': f'STU-MANIP-{idx}',
                'email': f'manip_{idx}@uni.edu',
                'username': uname,
                'password1': 'V3ryStr0ng!Pass2026',
                'password2': 'V3ryStr0ng!Pass2026',
            }
            data.update(extra)
            res = self.client.post(reverse('register'), data)
            self.assertEqual(res.status_code, 403)
            self.assertFalse(User.objects.filter(username=uname).exists())

    def test_instructor_cannot_self_approve_via_registration_post(self):
        res = self.client.post(reverse('register_instructor'), {
            'full_name': 'Self Approve Attempt',
            'department': 'CS',
            'email': 'selfapp@uni.edu',
            'username': 'self_approve_inst',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
            'status': 'APPROVED',
        })
        # Form succeeds only with PENDING profile; 'status' is not a form field so ignored
        self.assertRedirects(res, reverse('login'))
        user = User.objects.get(username='self_approve_inst')
        self.assertEqual(user.instructor_profile.status, 'PENDING')
        self.assertFalse(user.instructor_profile.is_authorized())

    def test_authenticated_users_cannot_register_or_escalate_via_registration_routes(self):
        self.client.force_login(self.existing_student)

        # GET redirects authenticated user away from registration
        res_get = self.client.get(reverse('register'))
        self.assertRedirects(res_get, reverse('student_dashboard'))

        # POST from authenticated user is strictly denied with 403
        res_post1 = self.client.post(reverse('register'), {
            'full_name': 'Extra Account',
            'student_id': 'STU-EXTRA',
            'email': 'extra@uni.edu',
            'username': 'extra_user',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
        })
        self.assertEqual(res_post1.status_code, 403)
        self.assertFalse(User.objects.filter(username='extra_user').exists())

        res_post2 = self.client.post(reverse('register_instructor'), {
            'full_name': 'Self Escalate',
            'department': 'CS',
            'email': 'escalate@uni.edu',
            'username': 'escalate_user',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
        })
        self.assertEqual(res_post2.status_code, 403)
        self.assertFalse(User.objects.filter(username='escalate_user').exists())
        self.existing_student.refresh_from_db()
        self.assertEqual(list(self.existing_student.groups.values_list('name', flat=True)), ['Student'])

    def test_duplicate_username_and_email_rejected_in_public_registration(self):
        # Duplicate username
        res1 = self.client.post(reverse('register'), {
            'full_name': 'Dup Username',
            'student_id': 'STU-DUP1',
            'email': 'unique_email@uni.edu',
            'username': 'existing_stu',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
        })
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(User.objects.filter(email='unique_email@uni.edu').count(), 0)

        # Duplicate email (case-insensitive)
        res2 = self.client.post(reverse('register'), {
            'full_name': 'Dup Email',
            'student_id': 'STU-DUP2',
            'email': 'EXISTING_STU@uni.edu',
            'username': 'brand_new_stu',
            'password1': 'V3ryStr0ng!Pass2026',
            'password2': 'V3ryStr0ng!Pass2026',
        })
        self.assertEqual(res2.status_code, 200)
        self.assertFalse(User.objects.filter(username='brand_new_stu').exists())


class Phase2CRoleAuthAndRedirectTests(TestCase):
    """
    Phase 2C Tests (14-23): Role-based authentication, cross-role isolation,
    pending/rejected instructor denial, unrecognized role handling, and open redirect prevention.
    """
    def setUp(self):
        self.password = 'V3ryStr0ng!Pass2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.admin_group, _ = Group.objects.get_or_create(name='Administrator')

        self.student = User.objects.create_user(username='stu_2c', email='stu2c@uni.edu', password=self.password)
        self.student.groups.add(self.student_group)

        self.approved_inst = User.objects.create_user(username='inst_app', email='app@uni.edu', password=self.password)
        self.approved_inst.groups.add(self.instructor_group)
        InstructorProfile.objects.create(user=self.approved_inst, full_name='Approved Inst', status='APPROVED')

        self.pending_inst = User.objects.create_user(username='inst_pend', email='pend@uni.edu', password=self.password)
        self.pending_inst.groups.add(self.instructor_group)
        InstructorProfile.objects.create(user=self.pending_inst, full_name='Pending Inst', status='PENDING')

        self.rejected_inst = User.objects.create_user(username='inst_rej', email='rej@uni.edu', password=self.password)
        self.rejected_inst.groups.add(self.instructor_group)
        InstructorProfile.objects.create(
            user=self.rejected_inst, full_name='Rejected Inst', status='REJECTED', rejection_reason='Unverified'
        )

        # Administrator WITHOUT is_superuser=True (Phase 2B least-privilege)
        self.admin_user = User.objects.create_user(
            username='admin_2c', email='admin2c@uni.edu', password=self.password, is_staff=True, is_superuser=False
        )
        self.admin_user.groups.add(self.admin_group)

        self.norole_user = User.objects.create_user(username='norole_2c', email='norole@uni.edu', password=self.password)

    def test_role_login_redirections_and_cross_role_denials(self):
        # Student -> student_dashboard, denied instructor & admin routes
        c_stu = Client()
        res_s = c_stu.post(reverse('login'), {'username': 'stu_2c', 'password': self.password})
        self.assertRedirects(res_s, reverse('student_dashboard'))
        self.assertEqual(c_stu.get(reverse('instructor_dashboard')).status_code, 403)
        self.assertEqual(c_stu.get(reverse('security_logs')).status_code, 403)

        # Approved Instructor -> instructor_dashboard, denied student & admin routes
        c_inst = Client()
        res_i = c_inst.post(reverse('login'), {'username': 'inst_app', 'password': self.password})
        self.assertRedirects(res_i, reverse('instructor_dashboard'))
        self.assertEqual(c_inst.get(reverse('student_dashboard')).status_code, 403)
        self.assertEqual(c_inst.get(reverse('security_logs')).status_code, 403)

        # Pending Instructor -> denied instructor features (403 with pending message)
        c_pend = Client()
        res_p = c_pend.post(reverse('login'), {'username': 'inst_pend', 'password': self.password}, follow=True)
        self.assertEqual(res_p.status_code, 403)
        self.assertContains(res_p, 'Pending Approval', status_code=403)

        # Rejected Instructor -> denied instructor features (403 with rejection reason)
        c_rej = Client()
        res_r = c_rej.post(reverse('login'), {'username': 'inst_rej', 'password': self.password}, follow=True)
        self.assertEqual(res_r.status_code, 403)
        self.assertContains(res_r, 'Unverified', status_code=403)

        # Administrator (is_superuser=False) -> security_logs 200
        c_adm = Client()
        res_a = c_adm.post(reverse('login'), {'username': 'admin_2c', 'password': self.password})
        self.assertRedirects(res_a, reverse('security_logs'))
        self.assertEqual(c_adm.get(reverse('security_logs')).status_code, 200)

    def test_unrecognized_role_denied_login_and_protected_routes(self):
        c = Client()
        res = c.post(reverse('login'), {'username': 'norole_2c', 'password': self.password})
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'does not have a valid securITquiz role')
        self.assertFalse(res.wsgi_request.user.is_authenticated)

        # Even if authenticated directly, all protected routes return 403
        c.force_login(self.norole_user)
        self.assertEqual(c.get(reverse('student_dashboard')).status_code, 403)
        self.assertEqual(c.get(reverse('instructor_dashboard')).status_code, 403)
        self.assertEqual(c.get(reverse('security_logs')).status_code, 403)

    def test_untrusted_next_open_redirect_prevented(self):
        for evil_next in ['https://evil.example.com/phish', '//evil.example.com/login', 'http://attacker.local/']:
            c = Client()
            res = c.post(f"{reverse('login')}?next={evil_next}", {
                'username': 'stu_2c',
                'password': self.password,
                'next': evil_next,
            })
            self.assertRedirects(res, reverse('student_dashboard'))
            c.post(reverse('logout'))

        # Safe local `next` redirect IS honored
        c2 = Client()
        res_safe = c2.post(reverse('login'), {
            'username': 'stu_2c',
            'password': self.password,
            'next': reverse('student_profile'),
        })
        self.assertRedirects(res_safe, reverse('student_profile'))


class Phase2CStudentSingleSessionTests(TestCase):
    """
    Phase 2C Tests (24-34): Strict single-active-session enforcement for Students,
    stale/deleted/corrupted/password-changed cleanup, concurrency protection,
    and unrestricted concurrent sessions for Instructors and Administrators.
    """
    def setUp(self):
        self.password = 'V3ryStr0ng!Pass2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')
        self.admin_group, _ = Group.objects.get_or_create(name='Administrator')

        self.student = User.objects.create_user(username='stu_single', email='stusingle@uni.edu', password=self.password)
        self.student.groups.add(self.student_group)

        self.instructor = User.objects.create_user(username='inst_multi', email='instmulti@uni.edu', password=self.password)
        self.instructor.groups.add(self.instructor_group)
        InstructorProfile.objects.create(user=self.instructor, full_name='Multi Inst', status='APPROVED')

        self.admin_user = User.objects.create_user(
            username='admin_multi', email='adminmulti@uni.edu', password=self.password, is_staff=True, is_superuser=False
        )
        self.admin_user.groups.add(self.admin_group)

    def test_deleted_django_session_does_not_permanently_lock_student(self):
        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        active = ActiveSession.objects.get(user=self.student)

        # Simulate Django session deletion / clearsessions while ActiveSession row remained
        Session.objects.filter(session_key=active.session_key).delete()

        c2 = Client()
        res2 = c2.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        self.assertRedirects(res2, reverse('student_dashboard'))
        self.assertEqual(c2.get(reverse('student_dashboard')).status_code, 200)

    def test_invalid_session_payload_and_password_change_invalidate_stale_lock(self):
        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        active = ActiveSession.objects.get(user=self.student)

        # 1. Corrupt Django session payload
        Session.objects.filter(session_key=active.session_key).update(session_data='corrupted-base64-data')
        c2 = Client()
        res2 = c2.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        self.assertRedirects(res2, reverse('student_dashboard'))

        # 2. Password change invalidates c2's _auth_user_hash
        new_pw = 'N3wStr0ng!Pass#2026'
        self.student.set_password(new_pw)
        self.student.save()

        c3 = Client()
        res3 = c3.post(reverse('login'), {'username': 'stu_single', 'password': new_pw})
        self.assertRedirects(res3, reverse('student_dashboard'))
        self.assertEqual(c3.get(reverse('student_dashboard')).status_code, 200)

    def test_concurrent_login_integrity_error_rejects_second_student_session(self):
        """Simulates concurrent race hitting ActiveSession OneToOne UNIQUE constraint."""
        from unittest.mock import patch
        from django.db import IntegrityError

        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        key1 = ActiveSession.objects.get(user=self.student).session_key

        c2 = Client()
        with patch('quiz.views.ActiveSession.objects.create', side_effect=IntegrityError('UNIQUE constraint failed')):
            res2 = c2.post(reverse('login'), {'username': 'stu_single', 'password': self.password})

        self.assertEqual(res2.status_code, 200)
        self.assertContains(res2, 'already has an active session')
        self.assertFalse(res2.wsgi_request.user.is_authenticated)
        self.assertEqual(ActiveSession.objects.get(user=self.student).session_key, key1)
        self.assertEqual(c1.get(reverse('student_dashboard')).status_code, 200)

    def test_device_switch_endpoint_cannot_bypass_student_single_session(self):
        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_single', 'password': self.password})
        key1 = ActiveSession.objects.get(user=self.student).session_key

        c2 = Client()
        session2 = c2.session
        session2['pending_switch_user_id'] = self.student.id
        session2['pending_switch_backend'] = 'django.contrib.auth.backends.ModelBackend'
        session2.save()

        res = c2.post(reverse('confirm_device_switch'))
        self.assertRedirects(res, reverse('login'))
        self.assertEqual(c2.get(reverse('student_dashboard')).status_code, 302)
        self.assertEqual(ActiveSession.objects.get(user=self.student).session_key, key1)
        self.assertEqual(c1.get(reverse('student_dashboard')).status_code, 200)

    def test_administrator_accounts_not_blocked_by_student_single_session(self):
        c1 = Client()
        res1 = c1.post(reverse('login'), {'username': 'admin_multi', 'password': self.password})
        self.assertRedirects(res1, reverse('security_logs'))

        c2 = Client()
        res2 = c2.post(reverse('login'), {'username': 'admin_multi', 'password': self.password})
        self.assertRedirects(res2, reverse('security_logs'))

        # Both administrator sessions remain authenticated simultaneously
        self.assertEqual(c1.get(reverse('security_logs')).status_code, 200)
        self.assertEqual(c2.get(reverse('security_logs')).status_code, 200)


class Phase2CSecureLogoutTests(TestCase):
    """
    Phase 2C Tests (35-40): POST-only logout, GET protection, CSRF enforcement,
    session invalidation, and scoped ActiveSession release.
    """
    def setUp(self):
        self.password = 'V3ryStr0ng!Pass2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.student = User.objects.create_user(username='stu_logout', email='stulogout@uni.edu', password=self.password)
        self.student.groups.add(self.student_group)

    def test_logout_invalidates_session_and_requires_csrf(self):
        csrf_client = Client(enforce_csrf_checks=True)
        login_page = csrf_client.get(reverse('login'))
        csrf_token = login_page.cookies['csrftoken'].value

        res_login = csrf_client.post(reverse('login'), {
            'username': 'stu_logout',
            'password': self.password,
            'csrfmiddlewaretoken': csrf_token,
        })
        self.assertRedirects(res_login, reverse('student_dashboard'))
        old_session_key = csrf_client.session.session_key
        self.assertTrue(Session.objects.filter(session_key=old_session_key).exists())

        # GET logout does not log out
        res_get = csrf_client.get(reverse('logout'))
        self.assertEqual(res_get.status_code, 405)
        self.assertTrue(Session.objects.filter(session_key=old_session_key).exists())

        # POST logout without CSRF token is rejected with 403
        res_nocsrf = csrf_client.post(reverse('logout'))
        self.assertEqual(res_nocsrf.status_code, 403)
        self.assertTrue(Session.objects.filter(session_key=old_session_key).exists())

        # POST logout with valid CSRF token succeeds and invalidates session
        new_csrf = csrf_client.cookies['csrftoken'].value
        res_post = csrf_client.post(reverse('logout'), {'csrfmiddlewaretoken': new_csrf})
        self.assertRedirects(res_post, reverse('login'))
        self.assertFalse(Session.objects.filter(session_key=old_session_key).exists())
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

    def test_one_session_cannot_clear_another_sessions_active_record(self):
        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_logout', 'password': self.password})
        key1 = ActiveSession.objects.get(user=self.student).session_key

        # Simulate a second unrelated session calling POST /logout/ while authenticated as same user
        c2 = Client()
        c2.force_login(self.student)
        self.assertNotEqual(c2.session.session_key, key1)

        c2.post(reverse('logout'))

        # Device 1's ActiveSession record MUST still exist and keep key1
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.session_key, key1)
        self.assertEqual(c1.get(reverse('student_dashboard')).status_code, 200)


class Phase2CAuditAndLogHygieneTests(TestCase):
    """
    Phase 2C Tests (41-44): Audit logging of duplicate logins and privilege escalation attempts,
    and ensuring passwords, hashes, and session keys are never written to logs.
    """
    def setUp(self):
        self.password = 'Sup3rSecret!Pw2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.student = User.objects.create_user(username='stu_audit2c', email='audit2c@uni.edu', password=self.password)
        self.student.groups.add(self.student_group)

    def test_logs_never_contain_passwords_hashes_or_session_keys(self):
        c1 = Client()
        c1.post(reverse('login'), {'username': 'stu_audit2c', 'password': self.password})
        key1 = c1.session.session_key

        # Trigger duplicate login block
        c2 = Client()
        c2.post(reverse('login'), {'username': 'stu_audit2c', 'password': self.password})

        # Trigger failed login
        c3 = Client()
        wrong_pw = 'WrongSecret!Pw999'
        c3.post(reverse('login'), {'username': 'stu_audit2c', 'password': wrong_pw})

        # Trigger unauthorized registration attempt
        c3.post(reverse('register'), {'username': 'x', 'role': 'Administrator'})

        # Trigger unauthorized role access attempt
        c1.get(reverse('security_logs'))

        self.assertTrue(AuditLog.objects.filter(action='CONCURRENT_LOGIN_BLOCKED').exists())
        self.assertTrue(AuditLog.objects.filter(action='UNAUTHORIZED_ACCESS_ATTEMPT').exists())

        for log in AuditLog.objects.all():
            self.assertNotIn(self.password, log.details)
            self.assertNotIn(wrong_pw, log.details)
            self.assertNotIn(self.student.password, log.details)
            if key1:
                self.assertNotIn(key1, log.details)


class Phase2CInactivityAndQuizSafetyTests(TestCase):
    """
    Phase 2C Correction Tests:
    - Configurable SESSION_INACTIVITY_TIMEOUT (default 1800s / 30 min).
    - Removal of base.html checkPendingAuth polling and ignoring passive polls in activity tracking.
    - Event-driven quiz answer auto-save and safe draft preservation on expired quiz POST.
    - Preservation of Student single-active-session enforcement and Instructor/Admin behavior.
    """
    def setUp(self):
        self.password = 'V3ryStr0ng!Pass2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.student = User.objects.create_user(
            username='stu_quiz_safety', email='safety@uni.edu', password=self.password
        )
        self.student.groups.add(self.student_group)

        self.instructor = User.objects.create_user(
            username='inst_quiz_safety', email='inst_safety@uni.edu', password=self.password
        )
        self.instructor.groups.add(self.instructor_group)
        InstructorProfile.objects.create(
            user=self.instructor, full_name='Prof Safety', status='APPROVED'
        )

        self.quiz = Quiz.objects.create(
            title='30-Min Cryptography Quiz',
            access_pin='SAFE26',
            time_limit_minutes=30,
            deadline=timezone.now() + timedelta(hours=2),
            created_by=self.instructor,
            is_active=True
        )
        self.q1 = Question.objects.create(
            quiz=self.quiz,
            question_text='Which hash is used with DSA?',
            question_type='MCQ',
            option_a='SHA-256',
            option_b='MD5',
            option_c='CRC32',
            option_d='ROT13',
            correct_answer='A'
        )
        self.q2 = Question.objects.create(
            quiz=self.quiz,
            question_text='DSA stands for Digital Signature Algorithm.',
            question_type='TF',
            correct_answer='True'
        )

    def test_inactivity_timeout_respects_overridden_setting(self):
        from django.conf import settings
        self.assertEqual(settings.SESSION_INACTIVITY_TIMEOUT, 1800)

        with override_settings(SESSION_INACTIVITY_TIMEOUT=120):
            c = Client()
            c.post(reverse('login'), {'username': 'stu_quiz_safety', 'password': self.password})
            active = ActiveSession.objects.get(user=self.student)

            # 90s is within 120s timeout
            active.last_activity = timezone.now() - timedelta(seconds=90)
            active.save()
            self.assertEqual(c.get(reverse('student_dashboard')).status_code, 200)

            # 125s exceeds 120s timeout -> expires
            active.refresh_from_db()
            active.last_activity = timezone.now() - timedelta(seconds=125)
            active.save()
            res = c.get(reverse('student_dashboard'))
            self.assertRedirects(res, reverse('login'))
            self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())

    def test_background_polling_does_not_extend_student_activity_and_removed_from_base(self):
        c = Client()
        c.post(reverse('login'), {'username': 'stu_quiz_safety', 'password': self.password})

        # Verify base.html no longer renders checkPendingAuth 3-second polling JS
        dash = c.get(reverse('student_dashboard'))
        self.assertEqual(dash.status_code, 200)
        self.assertNotContains(dash, 'checkPendingAuth')
        self.assertNotContains(dash, 'setInterval(checkPendingAuth')

        # Set last_activity 120s in the past (past the 30s throttle)
        past_time = timezone.now() - timedelta(seconds=120)
        ActiveSession.objects.filter(user=self.student).update(last_activity=past_time)

        # Hit passive polling endpoint directly -> must NOT update last_activity
        poll_res = c.get(reverse('pending_device_request'))
        self.assertEqual(poll_res.status_code, 200)
        active = ActiveSession.objects.get(user=self.student)
        self.assertEqual(active.last_activity, past_time)

        # Meaningful student request DOES extend last_activity
        c.get(reverse('student_dashboard'))
        active.refresh_from_db()
        self.assertGreater(active.last_activity, past_time)

    def test_active_quiz_autosave_and_inactivity_within_30_minutes(self):
        c = Client()
        c.post(reverse('login'), {'username': 'stu_quiz_safety', 'password': self.password})

        # Verify PIN and load quiz
        c.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'SAFE26'})
        quiz_page = c.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(quiz_page.status_code, 200)
        self.assertContains(quiz_page, 'triggerAutosave')

        # Autosave answer on meaningful change
        autosave_res = c.post(reverse('save_quiz_progress', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
        })
        self.assertEqual(autosave_res.status_code, 200)
        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(attempt.saved_answers.get(str(self.q1.id)), 'A')

        # 20 minutes into a 30-minute quiz (within 30-min SESSION_INACTIVITY_TIMEOUT), student remains authenticated
        ActiveSession.objects.filter(user=self.student).update(
            last_activity=timezone.now() - timedelta(minutes=20)
        )
        submit_res = c.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
            f'question_{self.q2.id}': 'True',
            'action': 'submit_all',
        })
        sub = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertRedirects(submit_res, reverse('quiz_result', args=[sub.id]))
        self.assertEqual(sub.score, 2.0)

    def test_quiz_submission_after_session_expiration_preserves_answers_safely(self):
        """
        If auth session expires right before final quiz POST:
        1. Middleware expires session and logs student out (SESSION_EXPIRED).
        2. Final submission is NOT executed unauthenticated; answers ARE safely preserved in QuizAttempt.
        3. After re-login & PIN re-verification, answers are pre-populated and submission succeeds with DSA.
        """
        c = Client()
        c.post(reverse('login'), {'username': 'stu_quiz_safety', 'password': self.password})
        c.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'SAFE26'})
        c.get(reverse('take_quiz', args=[self.quiz.id]))

        # Simulate > 30 minutes of inactivity while student was filling out quiz
        ActiveSession.objects.filter(user=self.student).update(
            last_activity=timezone.now() - timedelta(minutes=31)
        )

        # Student clicks Submit on expired session
        res = c.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
            f'question_{self.q2.id}': 'True',
            'action': 'submit_all',
        })

        # 1. Auth session expired and redirected to login -> verify-pin
        expected_next = reverse('verify_quiz_pin', args=[self.quiz.id])
        self.assertRedirects(res, f"{reverse('login')}?next={expected_next}")
        self.assertFalse(ActiveSession.objects.filter(user=self.student).exists())
        self.assertTrue(AuditLog.objects.filter(actor=self.student, action='SESSION_EXPIRED').exists())
        self.assertFalse(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).exists())

        # 2. Answers were safely preserved in QuizAttempt.saved_answers (not silently lost!)
        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz, is_completed=False)
        self.assertEqual(attempt.saved_answers.get(str(self.q1.id)), 'A')
        self.assertEqual(attempt.saved_answers.get(str(self.q2.id)), 'True')

        # 3. Student logs back in, re-verifies PIN, sees preserved answers, and completes submission
        c_new = Client()
        login_res = c_new.post(f"{reverse('login')}?next={expected_next}", {
            'username': 'stu_quiz_safety',
            'password': self.password,
            'next': expected_next,
        })
        self.assertRedirects(login_res, expected_next)

        pin_res = c_new.post(expected_next, {'access_pin': 'SAFE26'})
        self.assertRedirects(pin_res, reverse('take_quiz', args=[self.quiz.id]), fetch_redirect_response=False)

        resume_page = c_new.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(resume_page.status_code, 200)
        self.assertContains(resume_page, 'checked')

        final_res = c_new.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q1.id}': 'A',
            f'question_{self.q2.id}': 'True',
            'action': 'submit_all',
        })
        sub = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertRedirects(final_res, reverse('quiz_result', args=[sub.id]))
        self.assertEqual(sub.score, 2.0)
        self.assertTrue(verify_dsa_signature(
            self.student.username, self.quiz.id, sub.score, sub.percentage,
            sub.submitted_at.isoformat(), sub.dsa_signature,
            answers=sub.answers, signature_version=sub.signature_version
        ))

    def test_instructor_not_expired_by_student_inactivity_middleware(self):
        """Instructor sessions remain unaffected by Student-only inactivity middleware."""
        c1 = Client()
        c1.post(reverse('login'), {'username': 'inst_quiz_safety', 'password': self.password})
        c2 = Client()
        c2.post(reverse('login'), {'username': 'inst_quiz_safety', 'password': self.password})
        self.assertEqual(c1.get(reverse('instructor_dashboard')).status_code, 200)
        self.assertEqual(c2.get(reverse('instructor_dashboard')).status_code, 200)


class Phase2CSecurityReviewHardeningTests(TestCase):
    """
    Regression tests for Phase 2C security review findings:
    1. Expired/unauthenticated/revoked AJAX auto-save returns explicit JSON 401 (no HTML redirect).
    2. Auto-save vs final submission race prevention and row-lock serialization.
    3. quiz.is_active and duplicate QuizSubmission checks in auto-save & draft recovery.
    4. Model-level QuizAttempt.save_answers_from_post() validation & locked-question protection.
    5. Safe SESSION_INACTIVITY_TIMEOUT coercion and passive-poll non-extension of Django sessions.
    """
    def setUp(self):
        self.password = 'V3ryStr0ng!Pass2026'
        self.student_group, _ = Group.objects.get_or_create(name='Student')
        self.instructor_group, _ = Group.objects.get_or_create(name='Instructor')

        self.student = User.objects.create_user(
            username='stu_sec_review', email='secrev@uni.edu', password=self.password
        )
        self.student.groups.add(self.student_group)

        self.instructor = User.objects.create_user(
            username='inst_sec_review', email='inst_secrev@uni.edu', password=self.password
        )
        self.instructor.groups.add(self.instructor_group)
        InstructorProfile.objects.create(
            user=self.instructor, full_name='Prof Review', status='APPROVED'
        )

        self.quiz = Quiz.objects.create(
            title='Security Hardening Quiz',
            access_pin='HARD26',
            time_limit_minutes=30,
            deadline=timezone.now() + timedelta(hours=2),
            created_by=self.instructor,
            is_active=True
        )
        self.q_mcq = Question.objects.create(
            quiz=self.quiz,
            question_text='Pick SHA-256:',
            question_type='MCQ',
            option_a='SHA-256',
            option_b='MD5',
            option_c='DES',
            option_d='RC4',
            correct_answer='A'
        )
        self.q_tf = Question.objects.create(
            quiz=self.quiz,
            question_text='Argon2 hashes passwords.',
            question_type='TF',
            correct_answer='True'
        )
        self.q_id = Question.objects.create(
            quiz=self.quiz,
            question_text='Name the asymmetric signature algorithm:',
            question_type='ID',
            correct_answer='DSA'
        )

        # Foreign question on another quiz to verify cross-quiz isolation
        self.other_quiz = Quiz.objects.create(
            title='Other Quiz',
            access_pin='OTHR26',
            time_limit_minutes=15,
            deadline=timezone.now() + timedelta(hours=2),
            created_by=self.instructor,
            is_active=True
        )
        self.other_q = Question.objects.create(
            quiz=self.other_quiz,
            question_text='Foreign Q',
            question_type='MCQ',
            option_a='A', option_b='B', option_c='C', option_d='D',
            correct_answer='B'
        )

    def _login_and_enter_quiz(self, client):
        client.post(reverse('login'), {'username': 'stu_sec_review', 'password': self.password})
        client.post(reverse('verify_quiz_pin', args=[self.quiz.id]), {'access_pin': 'HARD26'})
        page = client.get(reverse('take_quiz', args=[self.quiz.id]))
        self.assertEqual(page.status_code, 200)
        return page

    def test_expired_ajax_autosave_returns_401_json_and_preserves_valid_draft(self):
        c = Client()
        self._login_and_enter_quiz(c)

        ActiveSession.objects.filter(user=self.student).update(
            last_activity=timezone.now() - timedelta(minutes=31)
        )

        # 1. Expired session on AJAX autosave returns explicit 401 JSON (never 302 login HTML)
        res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {
                f'question_{self.q_mcq.id}': 'A',
                f'question_{self.q_id.id}': 'DSA',
            },
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn('application/json', res['Content-Type'])
        payload = res.json()
        self.assertEqual(payload['status'], 'session_expired')
        self.assertTrue(payload['preserved'])
        self.assertIn('verify-pin', payload['login_url'])
        self.assertIn('preserved', payload['message'].lower())

        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz, is_completed=False)
        self.assertEqual(attempt.saved_answers.get(str(self.q_mcq.id)), 'A')
        self.assertEqual(attempt.saved_answers.get(str(self.q_id.id)), 'DSA')
        self.assertFalse(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).exists())

        # 2. Follow-up autosave after logout also returns 401 JSON with preserved=False
        res2 = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_tf.id}': 'True'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(res2.status_code, 401)
        self.assertIn('application/json', res2['Content-Type'])
        payload2 = res2.json()
        self.assertEqual(payload2['status'], 'session_expired')
        self.assertFalse(payload2['preserved'])
        attempt.refresh_from_db()
        self.assertNotIn(str(self.q_tf.id), attempt.saved_answers)

    def test_revoked_ajax_autosave_returns_401_json(self):
        c = Client()
        self._login_and_enter_quiz(c)
        ActiveSession.objects.filter(user=self.student).update(session_key='different_session_key_taken_over')

        res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'A'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(res.status_code, 401)
        payload = res.json()
        self.assertEqual(payload['status'], 'session_revoked')
        self.assertFalse(payload['preserved'])

    def test_take_quiz_template_contains_explicit_autosave_race_and_redirect_guards(self):
        c = Client()
        page = self._login_and_enter_quiz(c)
        self.assertContains(page, "redirect: 'manual'")
        self.assertContains(page, 'session-expired-banner')
        self.assertContains(page, 'cancelPendingAutosaves')
        self.assertContains(page, 'AbortController')
        self.assertContains(page, 'maxlength="200"')

    def test_autosave_rejects_after_final_submission_and_grades_latest_answers(self):
        c = Client()
        self._login_and_enter_quiz(c)

        # Autosave an initial answer then update it via autosave before final submit
        res1 = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'B', f'question_{self.q_tf.id}': 'False'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(res1.status_code, 200)

        res2 = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {
                f'question_{self.q_mcq.id}': 'A',
                f'question_{self.q_tf.id}': 'True',
                f'question_{self.q_id.id}': 'DSA',
            },
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(res2.status_code, 200)

        # Preserve session PIN artificially after submit to verify server-side rejection of late autosave
        session = c.session
        pin_snapshot = session.get(f'pin_verified_quiz_{self.quiz.id}')

        submit_res = c.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q_mcq.id}': 'A',
            f'question_{self.q_tf.id}': 'True',
            f'question_{self.q_id.id}': 'DSA',
            'action': 'submit_all',
        })
        sub = QuizSubmission.objects.get(student=self.student, quiz=self.quiz)
        self.assertRedirects(submit_res, reverse('quiz_result', args=[sub.id]))
        self.assertEqual(sub.score, 3.0)
        self.assertTrue(verify_dsa_signature(
            self.student.username, self.quiz.id, sub.score, sub.percentage,
            sub.submitted_at.isoformat(), sub.dsa_signature,
            answers=sub.answers, signature_version=sub.signature_version
        ))

        # Re-inject PIN flag and attempt late autosave -> blocked with 409 Conflict
        session = c.session
        session[f'pin_verified_quiz_{self.quiz.id}'] = pin_snapshot
        session.save()

        late_res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'D'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(late_res.status_code, 409)
        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        self.assertTrue(attempt.is_completed)
        self.assertEqual(attempt.saved_answers.get(str(self.q_mcq.id)), 'A')

        # Duplicate POST submit attempt redirects without creating a second QuizSubmission
        dup_submit = c.post(reverse('take_quiz', args=[self.quiz.id]), {
            f'question_{self.q_mcq.id}': 'D',
            'action': 'submit_all',
        })
        self.assertRedirects(dup_submit, reverse('quiz_result', args=[sub.id]))
        self.assertEqual(QuizSubmission.objects.filter(student=self.student, quiz=self.quiz).count(), 1)

    def test_inactive_quiz_and_duplicate_submission_blocked_in_autosave_and_draft_recovery(self):
        c = Client()
        self._login_and_enter_quiz(c)

        # Instructor deactivates quiz mid-attempt
        self.quiz.is_active = False
        self.quiz.save(update_fields=['is_active'])

        inactive_res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'A'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(inactive_res.status_code, 403)
        attempt = QuizAttempt.objects.get(student=self.student, quiz=self.quiz)
        self.assertEqual(attempt.saved_answers, {})

        # Expired session draft recovery must ALSO refuse saving when quiz is inactive
        ActiveSession.objects.filter(user=self.student).update(
            last_activity=timezone.now() - timedelta(minutes=31)
        )
        expired_inactive_res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'A'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(expired_inactive_res.status_code, 401)
        self.assertFalse(expired_inactive_res.json()['preserved'])
        attempt.refresh_from_db()
        self.assertEqual(attempt.saved_answers, {})

        # Re-login with active quiz and a pre-existing QuizSubmission -> draft recovery must not modify answers
        self.quiz.is_active = True
        self.quiz.save(update_fields=['is_active'])
        c2 = Client()
        self._login_and_enter_quiz(c2)
        QuizSubmission.objects.create(
            student=self.student, quiz=self.quiz, score=0.0, percentage=0.0,
            dsa_signature='sig', answers={}
        )
        ActiveSession.objects.filter(user=self.student).update(
            last_activity=timezone.now() - timedelta(minutes=31)
        )
        dup_expired_res = c2.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'A'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(dup_expired_res.status_code, 401)
        self.assertFalse(dup_expired_res.json()['preserved'])
        attempt.refresh_from_db()
        self.assertEqual(attempt.saved_answers, {})

    def test_model_level_save_answers_validation_and_locking(self):
        from django.core.exceptions import ValidationError

        attempt = QuizAttempt.objects.create(
            student=self.student,
            quiz=self.quiz,
            deadline=timezone.now() + timedelta(minutes=20),
            saved_answers={str(self.q_mcq.id): 'A'},
            locked_question_ids=[self.q_mcq.id],
        )

        # Locked question cannot be overwritten; foreign question ID is ignored; valid updates work
        changed = attempt.save_answers_from_post({
            f'question_{self.q_mcq.id}': 'D',
            f'question_{self.other_q.id}': 'B',
            f'question_{self.q_tf.id}': 'true',
            f'question_{self.q_id.id}': '',
        })
        self.assertTrue(changed)
        attempt.refresh_from_db()
        self.assertEqual(attempt.saved_answers[str(self.q_mcq.id)], 'A')
        self.assertEqual(attempt.saved_answers[str(self.q_tf.id)], 'True')
        self.assertEqual(attempt.saved_answers[str(self.q_id.id)], '')
        self.assertNotIn(str(self.other_q.id), attempt.saved_answers)

        # Unlock MCQ for invalid choice checks
        attempt.locked_question_ids = []
        attempt.save(update_fields=['locked_question_ids'])

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_mcq.id}': 'E'})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_tf.id}': 'Maybe'})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_id.id}': 'X' * 201})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_id.id}': 'DSA\x00bad'})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_id.id}': None})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_mcq.id}': ['A', 'B']})

        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post(['not-a-mapping'])

        # Expired attempt deadline rejected at model level
        attempt.deadline = timezone.now() - timedelta(seconds=10)
        attempt.save(update_fields=['deadline'])
        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_id.id}': 'DSA'})

        # Completed attempt rejected at model level
        attempt.deadline = timezone.now() + timedelta(minutes=20)
        attempt.is_completed = True
        attempt.save(update_fields=['deadline', 'is_completed'])
        with self.assertRaises(ValidationError):
            attempt.save_answers_from_post({f'question_{self.q_id.id}': 'DSA'})

        # Autosave view returns 400 JSON for invalid choice / oversized answer
        c = Client()
        attempt.delete()
        self._login_and_enter_quiz(c)
        bad_view_res = c.post(
            reverse('save_quiz_progress', args=[self.quiz.id]),
            {f'question_{self.q_mcq.id}': 'Z'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(bad_view_res.status_code, 400)
        self.assertEqual(bad_view_res.json()['status'], 'error')

    def test_inactivity_timeout_safe_coercion_and_session_save_every_request(self):
        from django.conf import settings
        from django.contrib.sessions.models import Session
        from quiz.models import get_session_inactivity_timeout_seconds

        self.assertFalse(settings.SESSION_SAVE_EVERY_REQUEST)

        with override_settings(SESSION_INACTIVITY_TIMEOUT='120'):
            self.assertEqual(get_session_inactivity_timeout_seconds(), 120)
            active = ActiveSession(
                user=self.student,
                session_key='abc',
                last_activity=timezone.now() - timedelta(seconds=130),
            )
            self.assertTrue(active.is_expired())

        with override_settings(SESSION_INACTIVITY_TIMEOUT='not-a-number'):
            self.assertEqual(get_session_inactivity_timeout_seconds(), 1800)

        with override_settings(SESSION_INACTIVITY_TIMEOUT=True):
            self.assertEqual(get_session_inactivity_timeout_seconds(), 1800)

        with override_settings(SESSION_INACTIVITY_TIMEOUT=-5):
            self.assertEqual(get_session_inactivity_timeout_seconds(), 1800)

        # Verify passive polling does NOT slide django_session.expire_date while active requests DO
        c = Client()
        c.post(reverse('login'), {'username': 'stu_sec_review', 'password': self.password})
        session_obj = Session.objects.get(session_key=c.session.session_key)
        past_expire = timezone.now() + timedelta(minutes=10)
        Session.objects.filter(pk=session_obj.pk).update(expire_date=past_expire)

        poll_res = c.get(reverse('pending_device_request'))
        self.assertEqual(poll_res.status_code, 200)
        session_obj.refresh_from_db()
        self.assertEqual(session_obj.expire_date, past_expire)

        dash_res = c.get(reverse('student_dashboard'))
        self.assertEqual(dash_res.status_code, 200)
        session_obj.refresh_from_db()
        self.assertGreater(session_obj.expire_date, past_expire + timedelta(minutes=40))
