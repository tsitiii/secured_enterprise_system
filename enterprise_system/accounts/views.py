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

from .models import (
    UserProfile, VerificationToken, LoginAttempt, PasswordResetToken,
    Role, RoleHierarchy, UserRole, RoleChangeRequest, 
    DataClassification, PermissionPolicy
)
from .serializers import (
    UserRegistrationSerializer, LoginSerializer, UserProfileSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    CaptchaVerificationSerializer, MFAVerifySerializer,
    UserListSerializer, UserDetailSerializer, UserUpdateSerializer,
    RoleSerializer, RoleHierarchySerializer, UserRoleSerializer,
    RoleAssignSerializer, RoleChangeRequestSerializer, RoleChangeRequestCreateSerializer,
    DataClassificationSerializer, DataClassifySerializer, PermissionCheckSerializer
)
from .utils import (
    generate_password_reset_token, send_password_reset_email,
    get_client_ip, generate_mfa_secret, generate_mfa_qr_code,
    verify_totp_code, generate_verification_token, send_verification_email
)

from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes


class RegisterView(APIView):
    """POST /api/auth/register - User registration with email verificationnn"""
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
            
            # Debug logging
            print(f"CAPTCHA Debug - Secret: {settings.RECAPTCHA_SECRET_KEY[:10]}...")
            print(f"CAPTCHA Debug - Token: {captcha_token[:20]}...")
            print(f"CAPTCHA Debug - Result: {result}")
            
            if result.get('success'):
                return Response({
                    'success': True,
                    'message': 'CAPTCHA verified successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'CAPTCHA verification failed',
                    'details': result.get('error-codes', [])
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


# ============================================================================
# Access Control & Policy Management Views
# ============================================================================

class RoleListView(generics.ListAPIView):
    """GET /api/admin/roles - List all defined roles and role hierarchies"""
    queryset = Role.objects.filter(is_active=True).prefetch_related('child_roles', 'parent_roles')
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        summary="List all roles and hierarchies",
        description="Get a list of all active roles with their hierarchies and user counts",
        responses={
            200: RoleSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Get roles with hierarchy information"""
        queryset = Role.objects.filter(is_active=True).prefetch_related(
            'child_roles__child_role',
            'parent_roles__parent_role'
        )
        return queryset


class RoleAssignView(APIView):
    """POST /api/admin/roles/assign - Assign or modify roles for users"""
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        request=RoleAssignSerializer,
        responses={
            200: UserRoleSerializer,
            400: OpenApiTypes.OBJECT,
            403: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Assign Role Success',
                value={
                    'id': 1,
                    'user': 1,
                    'username': 'john_doe',
                    'role': 2,
                    'role_name': 'Manager',
                    'assigned_by': 1,
                    'assigned_at': '2024-01-15T10:30:00Z',
                    'expires_at': None,
                    'is_active': True
                },
                response_only=True,
                status_codes=['200']
            )
        ]
    )
    def post(self, request):
        serializer = RoleAssignSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = serializer.validated_data['user_id']
        role_id = serializer.validated_data['role_id']
        expires_at = serializer.validated_data.get('expires_at')
        notes = serializer.validated_data.get('notes', '')
        
        try:
            user = User.objects.get(id=user_id)
            role = Role.objects.get(id=role_id, is_active=True)
        except (User.DoesNotExist, Role.DoesNotExist):
            return Response(
                {'error': 'User or role not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create or update user role assignment
        user_role, created = UserRole.objects.update_or_create(
            user=user,
            role=role,
            defaults={
                'assigned_by': request.user,
                'expires_at': expires_at,
                'notes': notes,
                'is_active': True
            }
        )
        
        response_serializer = UserRoleSerializer(user_role)
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class RoleChangeRequestView(APIView):
    """POST /api/admin/roles/request-change - Request temporary or dynamic role changes requiring approval"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        request=RoleChangeRequestCreateSerializer,
        responses={
            201: RoleChangeRequestSerializer,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Role Change Request',
                value={
                    'id': 1,
                    'user': 1,
                    'username': 'john_doe',
                    'requested_role': 2,
                    'requested_role_name': 'Manager',
                    'current_roles': ['Employee'],
                    'reason': 'Temporary promotion for project management',
                    'status': 'pending',
                    'requested_at': '2024-01-15T10:30:00Z',
                    'expires_at': '2024-02-15T10:30:00Z'
                },
                response_only=True,
                status_codes=['201']
            )
        ]
    )
    def post(self, request):
        serializer = RoleChangeRequestCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        role_id = serializer.validated_data['role_id']
        reason = serializer.validated_data['reason']
        expires_at = serializer.validated_data.get('expires_at')
        
        try:
            role = Role.objects.get(id=role_id, is_active=True)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Role not found or inactive'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get current roles for the user
        current_roles = list(
            UserRole.objects.filter(
                user=request.user, 
                is_active=True
            ).values_list('role__name', flat=True)
        )
        
        # Create role change request
        role_request = RoleChangeRequest.objects.create(
            user=request.user,
            requested_role=role,
            current_roles=current_roles,
            reason=reason,
            requested_by=request.user,
            expires_at=expires_at,
            status='pending'
        )
        
        response_serializer = RoleChangeRequestSerializer(role_request)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class DataClassifyView(APIView):
    """PATCH /api/data/classify - Assign security classifications (Confidential, Internal, Public)"""
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        request=DataClassifySerializer,
        responses={
            200: DataClassificationSerializer,
            201: DataClassificationSerializer,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Classify Data',
                value={
                    'id': 1,
                    'name': 'Financial Report Q4',
                    'classification': 'Confidential',
                    'description': 'Quarterly financial report',
                    'resource_type': 'document',
                    'resource_id': 'doc_12345',
                    'classified_by': 1,
                    'classified_at': '2024-01-15T10:30:00Z'
                },
                response_only=True,
                status_codes=['200', '201']
            )
        ]
    )
    def patch(self, request):
        serializer = DataClassifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        name = serializer.validated_data['name']
        classification = serializer.validated_data['classification']
        description = serializer.validated_data.get('description', '')
        resource_type = serializer.validated_data.get('resource_type', '')
        resource_id = serializer.validated_data.get('resource_id', '')
        
        # Create or update data classification
        data_classification, created = DataClassification.objects.update_or_create(
            name=name,
            defaults={
                'classification': classification,
                'description': description,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'classified_by': request.user
            }
        )
        
        response_serializer = DataClassificationSerializer(data_classification)
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        return Response(response_serializer.data, status=status_code)


class PermissionCheckView(APIView):
    """GET /api/permissions/check - Policy Decision Point (PDP) that evaluates role, department, location, and time"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        parameters=[
            OpenApiParameter('action', OpenApiTypes.STR, description='Action to check (e.g., read, write, delete)'),
            OpenApiParameter('resource_type', OpenApiTypes.STR, description='Type of resource', required=False),
            OpenApiParameter('resource_id', OpenApiTypes.STR, description='Resource identifier', required=False),
            OpenApiParameter('resource_classification', OpenApiTypes.STR, description='Resource classification level', required=False),
            OpenApiParameter('department', OpenApiTypes.STR, description='User department', required=False),
            OpenApiParameter('location', OpenApiTypes.STR, description='User location', required=False),
            OpenApiParameter('time', OpenApiTypes.DATETIME, description='Time context', required=False),
        ],
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Permission Check Result',
                value={
                    'allowed': True,
                    'reason': 'User has required role and meets policy conditions',
                    'evaluation': {
                        'rbac': {'allowed': True, 'roles': ['Manager', 'Employee']},
                        'abac': {'allowed': True, 'matched_policies': ['Policy 1']},
                        'mac': {'allowed': True, 'user_clearance': 'Confidential', 'resource_classification': 'Internal'}
                    }
                },
                response_only=True,
                status_codes=['200']
            )
        ]
    )
    def get(self, request):
        # Get query parameters
        action = request.query_params.get('action')
        resource_type = request.query_params.get('resource_type', '')
        resource_id = request.query_params.get('resource_id', '')
        resource_classification = request.query_params.get('resource_classification', '')
        department = request.query_params.get('department', '')
        location = request.query_params.get('location', '')
        time_str = request.query_params.get('time')
        
        if not action:
            return Response(
                {'error': 'action parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Parse time if provided
        request_time = None
        if time_str:
            try:
                from django.utils.dateparse import parse_datetime
                request_time = parse_datetime(time_str)
            except:
                pass
        
        if not request_time:
            request_time = timezone.now()
        
        # Evaluate permissions using RBAC, ABAC, and MAC
        evaluation = self._evaluate_permissions(
            user=request.user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_classification=resource_classification,
            department=department,
            location=location,
            time=request_time
        )
        
        # Determine final decision (deny by default if any check fails)
        allowed = (
            evaluation['rbac']['allowed'] and
            evaluation['abac']['allowed'] and
            evaluation['mac']['allowed']
        )
        
        return Response({
            'allowed': allowed,
            'reason': evaluation.get('reason', 'Permission evaluation completed'),
            'evaluation': evaluation
        }, status=status.HTTP_200_OK)
    
    def _evaluate_permissions(self, user, action, resource_type, resource_id, 
                              resource_classification, department, location, time):
        """Evaluate permissions using RBAC, ABAC, and MAC"""
        evaluation = {
            'rbac': {'allowed': False, 'roles': [], 'reason': ''},
            'abac': {'allowed': False, 'matched_policies': [], 'reason': ''},
            'mac': {'allowed': False, 'user_clearance': None, 'resource_classification': None, 'reason': ''},
            'reason': ''
        }
        
        # ========== RBAC Evaluation ==========
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).exclude(
            expires_at__lt=timezone.now()
        ).select_related('role')
        
        active_role_names = []
        for user_role in user_roles:
            if not user_role.is_expired():
                active_role_names.append(user_role.role.name)
                # Check if role has the required permission
                if action in user_role.role.permissions:
                    evaluation['rbac']['allowed'] = True
                    evaluation['rbac']['roles'] = active_role_names
                    evaluation['rbac']['reason'] = f'User has role with {action} permission'
                    break
        
        # If direct permission not found, check role hierarchy
        if not evaluation['rbac']['allowed']:
            # Get all parent roles through hierarchy
            for role_name in active_role_names:
                try:
                    role = Role.objects.get(name=role_name)
                    # Check parent roles
                    parent_roles = RoleHierarchy.objects.filter(child_role=role).select_related('parent_role')
                    for hierarchy in parent_roles:
                        parent_role = hierarchy.parent_role
                        if action in parent_role.permissions:
                            evaluation['rbac']['allowed'] = True
                            evaluation['rbac']['roles'] = active_role_names + [parent_role.name]
                            evaluation['rbac']['reason'] = f'User inherits permission from parent role {parent_role.name}'
                            break
                    if evaluation['rbac']['allowed']:
                        break
                except Role.DoesNotExist:
                    continue
        
        if not evaluation['rbac']['allowed']:
            evaluation['rbac']['roles'] = active_role_names
            evaluation['rbac']['reason'] = f'User roles do not have {action} permission'
        
        # ========== ABAC Evaluation ==========
        # Get active policies for this resource type and action
        policies = PermissionPolicy.objects.filter(
            is_active=True,
            action=action
        ).order_by('-priority')
        
        if resource_type:
            policies = policies.filter(
                models.Q(resource_type=resource_type) | models.Q(resource_type='')
            )
        
        if resource_classification:
            # Filter policies that match or are less restrictive
            classification_levels = ['Public', 'Internal', 'Confidential', 'Secret', 'Top Secret']
            try:
                required_level = classification_levels.index(resource_classification)
                allowed_levels = classification_levels[required_level:]
                policies = policies.filter(
                    models.Q(resource_classification__in=allowed_levels) | 
                    models.Q(resource_classification='')
                )
            except ValueError:
                pass
        
        matched_policies = []
        for policy in policies:
            if self._evaluate_policy_conditions(policy, user, active_role_names, department, location, time):
                matched_policies.append(policy.name)
                if policy.effect == 'allow':
                    evaluation['abac']['allowed'] = True
                    evaluation['abac']['matched_policies'] = matched_policies
                    evaluation['abac']['reason'] = f'Policy {policy.name} allows access'
                    break
                elif policy.effect == 'deny':
                    evaluation['abac']['allowed'] = False
                    evaluation['abac']['matched_policies'] = matched_policies
                    evaluation['abac']['reason'] = f'Policy {policy.name} denies access'
                    break
        
        if not matched_policies:
            # Default allow if no policies match (can be changed to deny by default)
            evaluation['abac']['allowed'] = True
            evaluation['abac']['reason'] = 'No policies matched, default allow'
        
        # ========== MAC Evaluation ==========
        if resource_classification:
            # Get user's highest clearance level from roles
            classification_levels = ['Public', 'Internal', 'Confidential', 'Secret', 'Top Secret']
            user_clearance = 'Public'  # Default
            
            # Check if user has roles with clearance levels
            for user_role in user_roles:
                role = user_role.role
                # Check if role name or permissions indicate clearance
                for level in reversed(classification_levels):
                    if level.lower() in role.name.lower() or level in role.permissions:
                        if classification_levels.index(level) > classification_levels.index(user_clearance):
                            user_clearance = level
                            break
            
            try:
                required_level = classification_levels.index(resource_classification)
                user_level = classification_levels.index(user_clearance)
                
                if user_level >= required_level:
                    evaluation['mac']['allowed'] = True
                    evaluation['mac']['user_clearance'] = user_clearance
                    evaluation['mac']['resource_classification'] = resource_classification
                    evaluation['mac']['reason'] = f'User clearance ({user_clearance}) meets required level ({resource_classification})'
                else:
                    evaluation['mac']['allowed'] = False
                    evaluation['mac']['user_clearance'] = user_clearance
                    evaluation['mac']['resource_classification'] = resource_classification
                    evaluation['mac']['reason'] = f'User clearance ({user_clearance}) insufficient for {resource_classification}'
            except ValueError:
                evaluation['mac']['allowed'] = False
                evaluation['mac']['reason'] = 'Invalid classification level'
        else:
            # No classification required, allow
            evaluation['mac']['allowed'] = True
            evaluation['mac']['reason'] = 'No classification required'
        
        return evaluation
    
    def _evaluate_policy_conditions(self, policy, user, user_roles, department, location, time):
        """Evaluate ABAC policy conditions"""
        conditions = policy.conditions
        
        # Check role condition
        if 'role' in conditions:
            required_roles = conditions['role']
            if isinstance(required_roles, list):
                if not any(role in user_roles for role in required_roles):
                    return False
        
        # Check department condition
        if 'department' in conditions:
            required_departments = conditions['department']
            if isinstance(required_departments, list):
                if department not in required_departments:
                    return False
        
        # Check location condition
        if 'location' in conditions:
            required_locations = conditions['location']
            if isinstance(required_locations, list):
                if location not in required_locations:
                    return False
        
        # Check time range condition
        if 'time_range' in conditions:
            time_range = conditions['time_range']
            if isinstance(time_range, dict):
                start_time = time_range.get('start')
                end_time = time_range.get('end')
                if start_time and end_time:
                    # Parse time strings (format: "HH:MM")
                    from datetime import datetime
                    try:
                        start = datetime.strptime(start_time, "%H:%M").time()
                        end = datetime.strptime(end_time, "%H:%M").time()
                        # time parameter is a datetime object, extract time component
                        from datetime import datetime as dt
                        if isinstance(time, dt):
                            current_time = time.time()
                        else:
                            current_time = timezone.now().time()
                        if not (start <= current_time <= end):
                            return False
                    except:
                        pass
        
        return True
