from django.urls import path
from . import views

urlpatterns = [
    # Authentication endpoints
    path('auth/register', views.RegisterView.as_view(), name='register'),
    path('auth/verify-captcha', views.VerifyCaptchaView.as_view(), name='verify-captcha'),
    path('auth/verify-email', views.VerifyEmailView.as_view(), name='verify-email'),
    path('auth/login', views.LoginView.as_view(), name='login'),
    path('auth/refresh', views.TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/mfa-challenge', views.MFAChallengeView.as_view(), name='mfa-challenge'),
    path('auth/mfa-setup', views.MFASetupView.as_view(), name='mfa-setup'),
    path('auth/mfa-enable', views.MFAEnableView.as_view(), name='mfa-enable'),
    path('auth/password-reset', views.PasswordResetView.as_view(), name='password-reset'),
    path('auth/password-reset/confirm', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # '''User profile endpoint (current user)'''
    
    path('user/profile', views.UserProfileView.as_view(), name='user-profile'),
    
    # User management endpoints
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
    
    # Access Control & Policy Management endpoints
    path('admin/roles', views.RoleListView.as_view(), name='role-list'),
    path('admin/roles/assign', views.RoleAssignView.as_view(), name='role-assign'),
    path('admin/roles/request-change', views.RoleChangeRequestView.as_view(), name='role-request-change'),
    path('data/classify', views.DataClassifyView.as_view(), name='data-classify'),
    path('permissions/check', views.PermissionCheckView.as_view(), name='permission-check'),
]

