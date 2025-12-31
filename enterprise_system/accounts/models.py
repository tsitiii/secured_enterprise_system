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


# ============================================================================
# Access Control & Policy Management Models (MAC, RBAC, ABAC)
# ============================================================================

class Role(models.Model):
    """Role-Based Access Control (RBAC) - Defines roles in the system"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Permissions associated with this role (stored as JSON or comma-separated)
    permissions = models.JSONField(default=list, blank=True, help_text="List of permission strings")
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_active']),
        ]


class RoleHierarchy(models.Model):
    """Defines hierarchical relationships between roles (e.g., Admin > Manager > Employee)"""
    parent_role = models.ForeignKey(
        Role, 
        on_delete=models.CASCADE, 
        related_name='child_roles',
        help_text="Higher-level role"
    )
    child_role = models.ForeignKey(
        Role, 
        on_delete=models.CASCADE, 
        related_name='parent_roles',
        help_text="Lower-level role that inherits from parent"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['parent_role', 'child_role']]
        verbose_name_plural = "Role Hierarchies"
        indexes = [
            models.Index(fields=['parent_role', 'child_role']),
        ]
    
    def __str__(self):
        return f"{self.parent_role.name} > {self.child_role.name}"


class UserRole(models.Model):
    """Assigns roles to users (RBAC)"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_assignments')
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='role_assignments_made'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Optional expiration for temporary roles")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True, help_text="Optional notes about this assignment")
    
    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
    
    def is_expired(self):
        """Check if role assignment has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    class Meta:
        unique_together = [['user', 'role']]
        indexes = [
            models.Index(fields=['user', 'role']),
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
        ]


class RoleChangeRequest(models.Model):
    """Requests for temporary or dynamic role changes requiring approval"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='role_change_requests')
    requested_role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='change_requests')
    current_roles = models.JSONField(default=list, help_text="Current roles of the user")
    reason = models.TextField(help_text="Reason for role change request")
    requested_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='role_requests_made',
        help_text="User who made the request"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="When the temporary role should expire")
    reviewed_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='role_requests_reviewed'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.requested_role.name} ({self.status})"
    
    def is_expired(self):
        """Check if request has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    class Meta:
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['status', 'requested_at']),
            models.Index(fields=['expires_at']),
        ]


class DataClassification(models.Model):
    """Mandatory Access Control (MAC) - Security classifications for data"""
    CLASSIFICATION_CHOICES = [
        ('Public', 'Public'),
        ('Internal', 'Internal'),
        ('Confidential', 'Confidential'),
        ('Secret', 'Secret'),
        ('Top Secret', 'Top Secret'),
    ]
    
    name = models.CharField(max_length=200, unique=True, help_text="Name/identifier for the data resource")
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    description = models.TextField(blank=True)
    resource_type = models.CharField(
        max_length=100, 
        blank=True,
        help_text="Type of resource (e.g., 'document', 'database', 'api_endpoint')"
    )
    resource_id = models.CharField(
        max_length=255, 
        blank=True,
        help_text="Identifier for the specific resource"
    )
    classified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='data_classifications')
    classified_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.classification}"
    
    class Meta:
        ordering = ['-classified_at']
        indexes = [
            models.Index(fields=['classification']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]


class PermissionPolicy(models.Model):
    """Attribute-Based Access Control (ABAC) - Policy rules for access decisions"""
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    
    # Policy conditions (stored as JSON for flexibility)
    # Example: {"role": ["admin", "manager"], "department": ["IT", "Finance"], "location": ["HQ"], "time_range": {"start": "09:00", "end": "17:00"}}
    conditions = models.JSONField(
        default=dict,
        help_text="Policy conditions (role, department, location, time, etc.)"
    )
    
    # Resource attributes this policy applies to
    resource_type = models.CharField(max_length=100, blank=True)
    resource_classification = models.CharField(
        max_length=20, 
        choices=DataClassification.CLASSIFICATION_CHOICES,
        blank=True,
        help_text="Minimum classification level required"
    )
    
    # Action allowed by this policy
    action = models.CharField(
        max_length=100,
        help_text="Action allowed (e.g., 'read', 'write', 'delete', 'execute')"
    )
    
    # Effect: allow or deny
    EFFECT_CHOICES = [
        ('allow', 'Allow'),
        ('deny', 'Deny'),
    ]
    effect = models.CharField(max_length=10, choices=EFFECT_CHOICES, default='allow')
    
    is_active = models.BooleanField(default=True)
    priority = models.IntegerField(default=0, help_text="Higher priority policies are evaluated first")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='policies_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} - {self.effect}"
    
    class Meta:
        ordering = ['-priority', 'name']
        verbose_name_plural = "Permission Policies"
        indexes = [
            models.Index(fields=['is_active', 'priority']),
            models.Index(fields=['resource_type', 'resource_classification']),
        ]