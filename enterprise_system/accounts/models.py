from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator
from django.conf import settings
import base64


class UserProfile(models.Model):
    """Extended user profile with security features"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")]
    )
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=255, blank=True, null=True)  # Encrypted TOTP secret
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} Profile"

    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False

    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save()

    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save()

    def increment_failed_attempts(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
        self.save()

    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.save()

    def encrypt_mfa_secret(self, secret):
        """Encrypt MFA secret before storing"""
        from cryptography.fernet import Fernet
        import hashlib
        # Generate a key from SECRET_KEY (Fernet needs 32 bytes, URL-safe base64 encoded)
        key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(key)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(secret.encode())
        return encrypted.decode()

    def decrypt_mfa_secret(self):
        """Decrypt stored MFA secret"""
        if not self.mfa_secret:
            return None
        try:
            from cryptography.fernet import Fernet
            import hashlib
            key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
            key = base64.urlsafe_b64encode(key)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(self.mfa_secret.encode())
            return decrypted.decode()
        except Exception:
            return None


class VerificationToken(models.Model):
    """Token for email/mobile verification"""
    TOKEN_TYPE_CHOICES = [
        ('email', 'Email'),
        ('phone', 'Phone'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.CharField(max_length=255, unique=True)
    token_type = models.CharField(max_length=10, choices=TOKEN_TYPE_CHOICES)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.token_type} verification for {self.user.username}"

    def is_valid(self):
        """Check if token is valid and not expired"""
        return not self.used and timezone.now() < self.expires_at

    class Meta:
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'token_type']),
        ]


class LoginAttempt(models.Model):
    """Track login attempts for security"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_attempts', null=True, blank=True)
    identifier = models.CharField(max_length=255)  # email or username
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['identifier', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
        ordering = ['-timestamp']


class PasswordResetToken(models.Model):
    """Secure password reset tokens"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username}"

    def is_valid(self):
        """Check if token is valid and not expired"""
        return not self.used and timezone.now() < self.expires_at

    class Meta:
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user']),
        ]
