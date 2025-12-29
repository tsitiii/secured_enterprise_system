from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from datetime import timedelta
from .models import UserProfile, VerificationToken, PasswordResetToken
from .utils import (
    generate_verification_token, send_verification_email, send_password_reset_email,
    validate_password_complexity, generate_mfa_secret, generate_mfa_qr_code,
    verify_totp_code
)


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(required=True)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    captcha_token = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 'phone_number', 'captcha_token', 'first_name', 'last_name')

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        
        # Validate password complexity
        complexity_errors = validate_password_complexity(attrs['password'])
        if complexity_errors:
            raise serializers.ValidationError({"password": complexity_errors})
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "A user with this email already exists"})
        
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm', None)
        validated_data.pop('captcha_token', None)
        phone_number = validated_data.pop('phone_number', None)
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            is_active=False  # Inactive until email is verified
        )
        
        # Get or create user profile (signal may have already created it)
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'phone_number': phone_number}
        )
        # If profile already exists, update phone_number if provided
        if not created and phone_number:
            profile.phone_number = phone_number
            profile.save()
        
        # Create and send email verification token
        token = generate_verification_token()
        VerificationToken.objects.create(
            user=user,
            token=token,
            token_type='email',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        # Send verification email
        send_verification_email(user, token, 'email')
        
        return user


class CaptchaVerificationSerializer(serializers.Serializer):
    """Serializer for CAPTCHA verification"""
    captcha_token = serializers.CharField(required=True)
    
    def validate_captcha_token(self, value):
        # TODO: Implement actual CAPTCHA verification (Google reCAPTCHA, hCaptcha, etc.)
        # For now, this is a placeholder
        # You would verify with the CAPTCHA provider's API here
        if not value:
            raise serializers.ValidationError("CAPTCHA token is required")
        return value


class LoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)


class MFASetupSerializer(serializers.Serializer):
    """Serializer for MFA setup"""
    pass  # MFA setup is handled in the view


class MFAVerifySerializer(serializers.Serializer):
    """Serializer for MFA code verification"""
    code = serializers.CharField(required=True, max_length=6)
    
    def validate_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("MFA code must be a 6-digit number")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            # Don't reveal if email exists for security
            raise serializers.ValidationError("If this email exists, a password reset link will be sent")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    token = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        
        # Validate password complexity
        complexity_errors = validate_password_complexity(attrs['password'])
        if complexity_errors:
            raise serializers.ValidationError({"password": complexity_errors})
        
        # Verify token
        try:
            reset_token = PasswordResetToken.objects.get(token=attrs['token'])
            if not reset_token.is_valid():
                raise serializers.ValidationError({"token": "Invalid or expired reset token"})
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Invalid reset token"})
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    mfa_enabled = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ('username', 'email', 'phone_number', 'first_name', 'last_name', 
                  'email_verified', 'phone_verified', 'mfa_enabled', 'created_at', 'updated_at')
        read_only_fields = ('email_verified', 'phone_verified', 'created_at', 'updated_at')

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        
        # Update user fields
        if user_data:
            user = instance.user
            if 'email' in user_data:
                user.email = user_data['email']
            if 'first_name' in user_data:
                user.first_name = user_data['first_name']
            if 'last_name' in user_data:
                user.last_name = user_data['last_name']
            user.save()
        
        # Update profile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        return instance


class UserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users (basic info)"""
    profile = serializers.SerializerMethodField()
    is_active = serializers.BooleanField(read_only=True)
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'is_active', 
                  'date_joined', 'last_login', 'profile')
        read_only_fields = ('id', 'username', 'email', 'is_active', 'date_joined', 'last_login')
    
    def get_profile(self, obj):
        """Get basic profile info"""
        try:
            profile = obj.profile
            return {
                'phone_number': profile.phone_number,
                'email_verified': profile.email_verified,
                'phone_verified': profile.phone_verified,
                'mfa_enabled': profile.mfa_enabled,
                'account_locked': profile.is_account_locked(),
            }
        except UserProfile.DoesNotExist:
            return None


class UserDetailSerializer(serializers.ModelSerializer):
    """Serializer for user detail view (full info)"""
    profile = serializers.SerializerMethodField()
    is_active = serializers.BooleanField()
    is_staff = serializers.BooleanField(read_only=True)
    is_superuser = serializers.BooleanField(read_only=True)
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'is_active', 
                  'is_staff', 'is_superuser', 'date_joined', 'last_login', 'profile')
    
    def get_profile(self, obj):
        """Get full profile info"""
        try:
            profile = obj.profile
            return {
                'phone_number': profile.phone_number,
                'email_verified': profile.email_verified,
                'phone_verified': profile.phone_verified,
                'mfa_enabled': profile.mfa_enabled,
                'failed_login_attempts': profile.failed_login_attempts,
                'account_locked_until': profile.account_locked_until,
                'account_locked': profile.is_account_locked(),
                'created_at': profile.created_at,
                'updated_at': profile.updated_at,
            }
        except UserProfile.DoesNotExist:
            return None


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user"""
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=False, validators=[validate_password])
    phone_number = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password', 'is_active', 'phone_number')
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def validate_password(self, value):
        """Validate password complexity if provided"""
        if value:
            complexity_errors = validate_password_complexity(value)
            if complexity_errors:
                raise serializers.ValidationError(complexity_errors)
        return value
    
    def update(self, instance, validated_data):
        """Update user and profile"""
        phone_number = validated_data.pop('phone_number', None)
        password = validated_data.pop('password', None)
        
        # Update password if provided
        if password:
            instance.set_password(password)
        
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update profile if phone_number provided
        if phone_number is not None:
            profile, created = UserProfile.objects.get_or_create(user=instance)
            profile.phone_number = phone_number
            profile.save()
        
        return instance

