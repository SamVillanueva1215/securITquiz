from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse

from quiz.models import StudentProfile


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
