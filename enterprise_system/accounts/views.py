from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django.db import transaction, models
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import requests

from .models import UserProfile, VerificationToken, LoginAttempt, PasswordResetToken
from .serializers import (
    UserRegistrationSerializer, LoginSerializer, UserProfileSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    CaptchaVerificationSerializer, MFAVerifySerializer,
    UserListSerializer, UserDetailSerializer,UserUpdateSerializer
)
from .utils import (
    generate_password_reset_token, send_password_reset_email,
    get_client_ip, generate_mfa_secret, generate_mfa_qr_code,
    verify_totp_code, generate_verification_token, send_verification_email
)

from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes


class RegisterView(APIView):
    """POST /api/auth/register - User registration with email verification"""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=UserRegistrationSerializer,
        responses={
            201: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Registration Success',
                value={
                    'message': 'Registration successful. Please check your email to verify your account.',
                    'user_id': 1
                },
                response_only=True,
                status_codes=['201']
            ),
            OpenApiExample(
                'Registration Error',
                value={
                    'username': ['This field is required.'],
                    'email': ['This field is required.'],
                    'password': ['This field is required.']
                },
                response_only=True,
                status_codes=['400']
            )
        ]
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyCaptchaView(APIView):
    """POST /api/auth/verify-captcha - Verify CAPTCHA token"""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=CaptchaVerificationSerializer,
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'CAPTCHA Success',
                value={
                    'success': True,
                    'message': 'CAPTCHA verified successfully'
                },
                response_only=True,
                status_codes=['200']
            ),
            OpenApiExample(
                'CAPTCHA Error',
                value={
                    'error': 'CAPTCHA verification failed'
                },
                response_only=True,
                status_codes=['400']
            )
        ]
    )
    def post(self, request):
        serializer = CaptchaVerificationSerializer(data=request.data)
        if serializer.is_valid():
            captcha_token = serializer.validated_data['captcha_token']
            
            # Verify with Google reCAPTCHA
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
                'secret': settings.RECAPTCHA_SECRET_KEY,
                'response': captcha_token
            })
            result = response.json()
            
            if result.get('success'):
                return Response({
                    'success': True,
                    'message': 'CAPTCHA verified successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'CAPTCHA verification failed'
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """POST /api/auth/login - User login with account lockout"""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
            401: OpenApiTypes.OBJECT,
            403: OpenApiTypes.OBJECT,
            423: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Login Success (No MFA)',
                value={
                    'access': 'eyJ0eXAiOiJKV1QiLCJhbGc...',
                    'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGc...',
                    'user': {
                        'id': 1,
                        'username': 'johndoe',
                        'email': 'john@example.com'
                    }
                },
                response_only=True,
                status_codes=['200']
            ),
            OpenApiExample(
                'MFA Required',
                value={
                    'message': 'MFA verification required',
                    'mfa_required': True,
                    'user_id': 1
                },
                response_only=True,
                status_codes=['200']
            ),
            OpenApiExample(
                'Invalid Credentials',
                value={
                    'error': 'Invalid credentials'
                },
                response_only=True,
                status_codes=['401']
            ),
            OpenApiExample(
                'Account Locked',
                value={
                    'error': 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
                    'locked_until': '2025-12-29T15:30:00Z'
                },
                response_only=True,
                status_codes=['423']
            )
        ]
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Try to find user by username or email
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                # Log failed attempt
                LoginAttempt.objects.create(
                    identifier=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False
                )
                return Response({
                    'error': 'Invalid credentials'
                }, status=status.HTTP_401_UNAUTHORIZED)

        # Get or create profile
        profile, created = UserProfile.objects.get_or_create(user=user)

        # Check if account is locked
        if profile.is_account_locked():
            return Response({
                'error': 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
                'locked_until': profile.account_locked_until
            }, status=status.HTTP_423_LOCKED)

        # Authenticate user
        user_auth = authenticate(username=user.username, password=password)

        if user_auth is None:
            # Log failed attempt
            profile.increment_failed_attempts()
            LoginAttempt.objects.create(
                user=user,
                identifier=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False
            )
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check if account is active
        if not user.is_active:
            return Response({
                'error': 'Account is not active. Please verify your email first.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Reset failed attempts on successful login
        profile.reset_failed_attempts()

        # Log successful attempt
        LoginAttempt.objects.create(
            user=user,
            identifier=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )

        # Check if MFA is enabled
        if profile.mfa_enabled:
            return Response({
                'message': 'MFA verification required',
                'mfa_required': True,
                'user_id': user.id
            }, status=status.HTTP_200_OK)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    """POST /api/auth/refresh - Refresh JWT access token"""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=OpenApiTypes.OBJECT,
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
            401: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Refresh Success',
                value={
                    'access': 'eyJ0eXAiOiJKV1QiLCJhbGc...',
                    'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGc...'
                },
                response_only=True,
                status_codes=['200']
            ),
            OpenApiExample(
                'Missing Token',
                value={
                    'error': 'Refresh token is required'
                },
                response_only=True,
                status_codes=['400']
            ),
            OpenApiExample(
                'Invalid Token',
                value={
                    'error': 'Invalid refresh token'
                },
                response_only=True,
                status_codes=['401']
            )
        ]
    )
    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({
                'error': 'Refresh token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            refresh = RefreshToken(refresh_token)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)


class MFAChallengeView(APIView):
    """POST /api/auth/mfa-challenge - MFA verification"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_id = request.data.get('user_id')
        code = serializer.validated_data['code']

        try:
            user = User.objects.get(id=user_id)
            profile = user.profile
        except (User.DoesNotExist, UserProfile.DoesNotExist):
            return Response({
                'error': 'Invalid user'
            }, status=status.HTTP_404_NOT_FOUND)

        if not profile.mfa_enabled:
            return Response({
                'error': 'MFA is not enabled for this account'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Decrypt and verify MFA secret
        mfa_secret = profile.decrypt_mfa_secret()
        if not mfa_secret or not verify_totp_code(mfa_secret, code):
            return Response({
                'error': 'Invalid MFA code'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_200_OK)


class MFASetupView(APIView):
    """POST /api/auth/mfa-setup - Setup MFA for user"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        profile, created = UserProfile.objects.get_or_create(user=user)

        if profile.mfa_enabled:
            return Response({
                'error': 'MFA is already enabled'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate MFA secret
        secret = generate_mfa_secret()
        encrypted_secret = profile.encrypt_mfa_secret(secret)

        # Store encrypted secret (but don't enable yet)
        profile.mfa_secret = encrypted_secret
        profile.save()

        # Generate QR code
        qr_code = generate_mfa_qr_code(user, secret)

        return Response({
            'secret': secret,  # Return secret for user to manually enter if needed
            'qr_code': qr_code,
            'message': 'Scan QR code with authenticator app, then verify with a code to enable MFA'
        }, status=status.HTTP_200_OK)


class MFAEnableView(APIView):
    """POST /api/auth/mfa-enable - Enable MFA after verification"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        profile = user.profile
        code = serializer.validated_data['code']

        if not profile.mfa_secret:
            return Response({
                'error': 'MFA secret not found. Please setup MFA first.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify the code
        mfa_secret = profile.decrypt_mfa_secret()
        if not verify_totp_code(mfa_secret, code):
            return Response({
                'error': 'Invalid MFA code'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Enable MFA
        profile.mfa_enabled = True
        profile.save()

        return Response({
            'message': 'MFA enabled successfully'
        }, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    """POST /api/auth/password-reset - Request password reset"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't reveal if email exists for security
            return Response({
                'message': 'If this email exists, a password reset link has been sent.'
            }, status=status.HTTP_200_OK)

        # Generate reset token
        token = generate_password_reset_token()
        PasswordResetToken.objects.create(
            user=user,
            token=token,
            expires_at=timezone.now() + timedelta(hours=1)
        )

        # Send reset email
        send_password_reset_email(user, token)

        return Response({
            'message': 'If this email exists, a password reset link has been sent.'
        }, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """POST /api/auth/password-reset/confirm - Confirm password reset"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data['token']
        password = serializer.validated_data['password']

        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            if not reset_token.is_valid():
                return Response({
                    'error': 'Invalid or expired reset token'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update password
            user = reset_token.user
            user.set_password(password)
            user.save()

            # Mark token as used
            reset_token.used = True
            reset_token.save()

            # Reset failed login attempts
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.unlock_account()

            return Response({
                'message': 'Password reset successfully'
            }, status=status.HTTP_200_OK)

        except PasswordResetToken.DoesNotExist:
            return Response({
                'error': 'Invalid reset token'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """GET/PUT /api/user/profile - Get and update user profile"""
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile


class VerifyEmailView(APIView):
    """POST /api/auth/verify-email - Verify user email with token"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            verification = VerificationToken.objects.get(token=token)
        except VerificationToken.DoesNotExist:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        if not verification.is_valid():
            return Response({'error': 'Token has expired or already used.'}, status=status.HTTP_400_BAD_REQUEST)

        user = verification.user
        user.is_active = True
        user.save()
        verification.delete()

        return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)

class UserListView(generics.ListAPIView):
    """GET /api/users/ - List all users (Admin only)"""
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAdminUser]
    
    def get_queryset(self):
        """Filter users based on query parameters"""
        queryset = User.objects.all().order_by('-date_joined')
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Filter by search term (username, email, first_name, last_name)
        search = self.request.query_params.get('search', None)
        if search:
            from django.db.models import Q
            queryset = queryset.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        return queryset


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """GET/PUT/PATCH/DELETE /api/users/{id}/ - User detail operations"""
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_permissions(self):
        """Allow users to view their own profile, admins can do everything"""
        if self.request.method == 'GET':
            # Users can view their own profile, admins can view any
            return [permissions.IsAuthenticated()]
        elif self.request.method in ['PUT', 'PATCH']:
            # Users can update their own profile, admins can update any
            return [permissions.IsAuthenticated()]
        elif self.request.method == 'DELETE':
            # Only admins can delete users
            return [permissions.IsAdminUser()]
        return super().get_permissions()
    
    def get_serializer_class(self):
        """Use different serializer for update"""
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserDetailSerializer
    
    def get_object(self):
        """Allow users to access their own profile, admins can access any"""
        obj = super().get_object()
        
        # Admins can access any user
        if self.request.user.is_staff:
            return obj
        
        # Regular users can only access their own profile
        if obj != self.request.user:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You can only access your own profile.")
        
        return obj
    
    def destroy(self, request, *args, **kwargs):
        """Prevent users from deleting themselves"""
        instance = self.get_object()
        
        # Prevent users from deleting themselves
        if instance == request.user:
            return Response(
                {'error': 'You cannot delete your own account. Contact an administrator.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Soft delete: deactivate instead of actually deleting
        instance.is_active = False
        instance.save()
        
        return Response(
            {'message': f'User {instance.username} has been deactivated.'},
            status=status.HTTP_200_OK
        )
