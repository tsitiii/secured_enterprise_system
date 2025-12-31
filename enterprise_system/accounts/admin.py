from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import (
    UserProfile, VerificationToken, LoginAttempt, PasswordResetToken,
    Role, RoleHierarchy, UserRole, RoleChangeRequest,
    DataClassification, PermissionPolicy
)


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'


class CustomUserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super().get_inline_instances(request, obj)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token_type', 'created_at', 'expires_at', 'used')
    list_filter = ('token_type', 'used', 'created_at')
    search_fields = ('user__username', 'user__email', 'token')
    readonly_fields = ('token', 'created_at')


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'identifier', 'ip_address', 'success', 'timestamp')
    list_filter = ('success', 'timestamp')
    search_fields = ('identifier', 'ip_address', 'user__username')
    readonly_fields = ('timestamp',)


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'used')
    list_filter = ('used', 'created_at')
    search_fields = ('user__username', 'user__email', 'token')
    readonly_fields = ('token', 'created_at')


# Access Control & Policy Management Admin
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description')
    filter_horizontal = ()  # Can be used for permissions if needed


@admin.register(RoleHierarchy)
class RoleHierarchyAdmin(admin.ModelAdmin):
    list_display = ('parent_role', 'child_role', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('parent_role__name', 'child_role__name')


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'is_active', 'assigned_at', 'expires_at', 'assigned_by')
    list_filter = ('is_active', 'role', 'assigned_at')
    search_fields = ('user__username', 'user__email', 'role__name')
    readonly_fields = ('assigned_at',)


@admin.register(RoleChangeRequest)
class RoleChangeRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'requested_role', 'status', 'requested_at', 'reviewed_by')
    list_filter = ('status', 'requested_at', 'requested_role')
    search_fields = ('user__username', 'requested_role__name', 'reason')
    readonly_fields = ('requested_at', 'current_roles')
    actions = ['approve_requests', 'reject_requests']
    
    def approve_requests(self, request, queryset):
        """Approve selected role change requests"""
        from django.utils import timezone
        for req in queryset.filter(status='pending'):
            req.status = 'approved'
            req.reviewed_by = request.user
            req.reviewed_at = timezone.now()
            req.save()
            
            # Create user role assignment
            UserRole.objects.create(
                user=req.user,
                role=req.requested_role,
                assigned_by=request.user,
                expires_at=req.expires_at,
                notes=f'Approved from role change request #{req.id}'
            )
        self.message_user(request, f"{queryset.count()} requests approved.")
    approve_requests.short_description = "Approve selected requests"
    
    def reject_requests(self, request, queryset):
        """Reject selected role change requests"""
        from django.utils import timezone
        for req in queryset.filter(status='pending'):
            req.status = 'rejected'
            req.reviewed_by = request.user
            req.reviewed_at = timezone.now()
            req.save()
        self.message_user(request, f"{queryset.count()} requests rejected.")


@admin.register(DataClassification)
class DataClassificationAdmin(admin.ModelAdmin):
    list_display = ('name', 'classification', 'resource_type', 'classified_by', 'classified_at')
    list_filter = ('classification', 'resource_type', 'classified_at')
    search_fields = ('name', 'description', 'resource_id')
    readonly_fields = ('classified_at', 'classified_by')


@admin.register(PermissionPolicy)
class PermissionPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'action', 'effect', 'is_active', 'priority', 'created_at')
    list_filter = ('is_active', 'effect', 'action', 'resource_type', 'priority')
    search_fields = ('name', 'description', 'action')
    readonly_fields = ('created_at', 'created_by')
