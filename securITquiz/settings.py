"""
Django settings for securITquiz project.
"""

import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
import dj_database_url

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent

# Environment detection
IS_VERCEL = bool(os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'))
IS_PRODUCTION = IS_VERCEL or os.environ.get('ENVIRONMENT') == 'production' or os.environ.get('DJANGO_PRODUCTION', '').lower() in ('true', '1')

# Secret Key Configuration
_secret_key = os.environ.get('DJANGO_SECRET_KEY', '').strip()
if IS_PRODUCTION:
    if not _secret_key:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY environment variable is missing or empty. "
            "A secure SECRET_KEY must be configured in Vercel/production."
        )
    SECRET_KEY = _secret_key
else:
    # Local development fallback
    SECRET_KEY = _secret_key if _secret_key else 'django-insecure-(6*um74ynlw%k8+r+o$fjbdsa&pezpkoq@h6u6oh#=)(j9it-^'

# Debug: default to False on Vercel unless DJANGO_DEBUG is explicitly 'true'
DEBUG = False if IS_PRODUCTION else (
    os.environ.get('DJANGO_DEBUG', 'True').lower() in ('true', '1')
)

# Allowed Hosts: explicit environment configuration takes priority
allowed_hosts_env = os.environ.get('DJANGO_ALLOWED_HOSTS')

if allowed_hosts_env:
    ALLOWED_HOSTS = [
        host.strip()
        for host in allowed_hosts_env.split(',')
        if host.strip()
    ]
elif IS_PRODUCTION:
    ALLOWED_HOSTS = ['securitquiz.vercel.app']
else:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']

# CSRF Trusted Origins: read DJANGO_CSRF_TRUSTED_ORIGINS or sensible defaults
csrf_trusted_env = os.environ.get('DJANGO_CSRF_TRUSTED_ORIGINS')
if csrf_trusted_env:
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in csrf_trusted_env.split(',') if origin.strip()]
else:
    CSRF_TRUSTED_ORIGINS = [
        'https://*.vercel.app',
        'https://securitquiz.vercel.app',
        'http://127.0.0.1',
        'http://localhost',
    ]

# Reverse Proxy SSL Header for Vercel edge deployment
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'quiz',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'quiz.middleware.SingleActiveSessionMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'securITquiz.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'securITquiz.wsgi.application'

# Serverless / Read-Only Filesystem support (Vercel, AWS Lambda)
IS_SERVERLESS = bool(IS_VERCEL or not os.access(BASE_DIR, os.W_OK))

# Database configuration
# In production/Vercel: Neon PostgreSQL is required via DATABASE_URL.
# In local development: SQLite is used at BASE_DIR / 'db.sqlite3' if DATABASE_URL is unset.
database_url = os.environ.get('DATABASE_URL', '').strip()

if IS_PRODUCTION:
    if not database_url:
        raise ImproperlyConfigured(
            "DATABASE_URL environment variable is missing or empty. "
            "A valid PostgreSQL connection must be configured in Vercel/production."
        )
    try:
        db_config = dj_database_url.parse(database_url, conn_max_age=0, ssl_require=True)
    except Exception:
        raise ImproperlyConfigured(
            "DATABASE_URL is invalid or unparseable. "
            "Please check the PostgreSQL connection configuration."
        ) from None

    if not db_config or db_config.get('ENGINE') != 'django.db.backends.postgresql':
        raise ImproperlyConfigured(
            "DATABASE_URL must configure a PostgreSQL database (django.db.backends.postgresql). "
            f"Configured engine: {db_config.get('ENGINE') if db_config else 'None'}."
        )
    DATABASES = {
        'default': db_config,
    }
elif database_url:
    try:
        db_config = dj_database_url.parse(database_url, conn_max_age=0, ssl_require=True)
    except Exception:
        raise ImproperlyConfigured(
            "DATABASE_URL is invalid or unparseable. "
            "Please check the PostgreSQL connection configuration."
        ) from None
    DATABASES = {
        'default': db_config,
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Password Security: Argon2 with fallbacks
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

# Authentication Backends: Allow login via Username OR Email
AUTHENTICATION_BACKENDS = [
    'quiz.backends.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend',
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Session Security Configuration
# Cookie lifetime (exceeds inactivity timeout so middleware can intercept expired sessions and log SESSION_EXPIRED)
SESSION_COOKIE_AGE = 3600
# Student inactivity expiration window in seconds (default 30 minutes / 1800s, enforced by SingleActiveSessionMiddleware)
SESSION_INACTIVITY_TIMEOUT = 1800
# Disabled globally so passive polling cannot trigger DB session writes or refresh cookie expiry;
# SingleActiveSessionMiddleware slides request.session.modified on meaningful authenticated requests.
SESSION_SAVE_EVERY_REQUEST = False

# Cookie Security Settings (Part 4.5 & Part 10)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG

# Security Headers & Clickjacking Protection
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True

# Email Configuration via Environment Variables with Safe Console Fallback
EMAIL_BACKEND = os.environ.get('DJANGO_EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.environ.get('DJANGO_EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.environ.get('DJANGO_EMAIL_PORT', 587))
EMAIL_USE_TLS = os.environ.get('DJANGO_EMAIL_USE_TLS', 'True').lower() in ('true', '1')
EMAIL_HOST_USER = os.environ.get('DJANGO_EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('DJANGO_EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DJANGO_DEFAULT_FROM_EMAIL', 'noreply@securitquiz.edu')
