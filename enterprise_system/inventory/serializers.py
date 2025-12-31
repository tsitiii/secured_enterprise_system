from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils import timezone
from .models import (
    InventoryItem, ResourcePermission, PermissionLog,
    PurchaseOrder, ApprovalRule,
    UserActivityLog, SystemEvent, Backup, SecurityAlert
)


# ============================================================================
# Inventory & Resource Management (DAC) Serializers
# ============================================================================

class InventoryItemSerializer(serializers.ModelSerializer):
    """Serializer for inventory items"""
    owner_username = serializers.CharField(source='owner.username', read_only=True)
    owner_email = serializers.EmailField(source='owner.email', read_only=True)
    permissions_count = serializers.SerializerMethodField()
    
    class Meta:
        model = InventoryItem
        fields = (
            'id', 'name', 'description', 'category', 'quantity', 
            'unit_price', 'location', 'department', 'owner', 
            'owner_username', 'owner_email', 'permissions_count',
            'created_at', 'updated_at', 'is_active'
        )
        read_only_fields = ('id', 'created_at', 'updated_at', 'owner')
    
    def get_permissions_count(self, obj):
        """Get count of active permissions on this resource"""
        return obj.permissions.filter(is_active=True).count()
    
    def create(self, validated_data):
        """Set the owner to the current user"""
        validated_data['owner'] = self.context['request'].user
        return super().create(validated_data)


class ResourcePermissionSerializer(serializers.ModelSerializer):
    """Serializer for resource permissions (DAC)"""
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.EmailField(source='user.email', read_only=True)
    resource_name = serializers.CharField(source='resource.name', read_only=True)
    granted_by_username = serializers.CharField(source='granted_by.username', read_only=True, allow_null=True)
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = ResourcePermission
        fields = (
            'id', 'resource', 'resource_name', 'user', 'user_username', 
            'user_email', 'permission_type', 'granted_by', 'granted_by_username',
            'granted_at', 'expires_at', 'is_active', 'notes', 'is_expired'
        )
        read_only_fields = ('id', 'granted_at', 'granted_by')
    
    def get_is_expired(self, obj):
        return obj.is_expired()


class ResourceShareSerializer(serializers.Serializer):
    """Serializer for sharing resources (granting permissions)"""
    resource_id = serializers.IntegerField(required=True)
    user_id = serializers.IntegerField(required=True)
    permission_type = serializers.ChoiceField(
        choices=ResourcePermission.PERMISSION_TYPES,
        required=True
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    def validate_resource_id(self, value):
        try:
            resource = InventoryItem.objects.get(id=value)
            # Check if current user is the owner
            request = self.context.get('request')
            if request and request.user != resource.owner:
                raise serializers.ValidationError("Only the resource owner can grant permissions")
        except InventoryItem.DoesNotExist:
            raise serializers.ValidationError("Resource not found")
        return value
    
    def validate_user_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        return value


class PermissionLogSerializer(serializers.ModelSerializer):
    """Serializer for permission audit logs"""
    username = serializers.CharField(source='user.username', read_only=True, allow_null=True)
    resource_name = serializers.CharField(source='resource.name', read_only=True)
    
    class Meta:
        model = PermissionLog
        fields = (
            'id', 'resource', 'resource_name', 'user', 'username',
            'action', 'details', 'ip_address', 'user_agent', 'timestamp'
        )
        read_only_fields = ('id', 'timestamp')


# ============================================================================
# Procurement & Rule-Based Access Control (RuBAC) Serializers
# ============================================================================

class PurchaseOrderSerializer(serializers.ModelSerializer):
    """Serializer for purchase orders"""
    requested_by_username = serializers.CharField(source='requested_by.username', read_only=True)
    requested_by_email = serializers.EmailField(source='requested_by.email', read_only=True)
    approved_by_username = serializers.CharField(source='approved_by.username', read_only=True, allow_null=True)
    
    class Meta:
        model = PurchaseOrder
        fields = (
            'id', 'po_number', 'description', 'total_amount', 'vendor',
            'requested_by', 'requested_by_username', 'requested_by_email',
            'department', 'status', 'approved_by', 'approved_by_username',
            'approval_notes', 'requested_at', 'approved_at', 
            'required_approval_date', 'requires_approval', 'approval_rule_applied'
        )
        read_only_fields = (
            'id', 'po_number', 'requested_at', 'approved_at', 
            'requires_approval', 'approval_rule_applied', 'status'
        )
    
    def create(self, validated_data):
        """Set requester and generate PO number"""
        validated_data['requested_by'] = self.context['request'].user
        
        # Generate PO number
        import random
        import string
        po_number = f"PO-{timezone.now().strftime('%Y%m%d')}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
        validated_data['po_number'] = po_number
        
        # Apply approval rules
        po = PurchaseOrder(**validated_data)
        po._apply_approval_rules()
        po.save()
        
        return po


class PurchaseOrderCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating purchase orders"""
    
    class Meta:
        model = PurchaseOrder
        fields = (
            'description', 'total_amount', 'vendor', 'department',
            'required_approval_date'
        )
    
    def create(self, validated_data):
        """Set requester and generate PO number"""
        validated_data['requested_by'] = self.context['request'].user
        
        # Generate PO number
        import random
        import string
        po_number = f"PO-{timezone.now().strftime('%Y%m%d')}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
        validated_data['po_number'] = po_number
        validated_data['status'] = 'submitted'
        
        # Create PO
        po = PurchaseOrder.objects.create(**validated_data)
        
        # Apply approval rules
        po._apply_approval_rules()
        po.save()
        
        return po


class ApprovalRuleSerializer(serializers.ModelSerializer):
    """Serializer for approval rules"""
    
    class Meta:
        model = ApprovalRule
        fields = (
            'id', 'name', 'description', 'min_amount', 'max_amount',
            'required_roles', 'required_departments', 'working_hours_only',
            'working_hours_start', 'working_hours_end', 'is_active', 
            'priority', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'created_at', 'updated_at')


# ============================================================================
# Audit, Logging & System Health Serializers
# ============================================================================

class UserActivityLogSerializer(serializers.ModelSerializer):
    """Serializer for user activity logs"""
    
    class Meta:
        model = UserActivityLog
        fields = (
            'id', 'user', 'username', 'action', 'resource_type', 
            'resource_id', 'details', 'ip_address', 'user_agent', 'timestamp'
        )
        read_only_fields = ('id', 'timestamp')


class SystemEventSerializer(serializers.ModelSerializer):
    """Serializer for system events"""
    triggered_by_username = serializers.CharField(
        source='triggered_by.username', 
        read_only=True, 
        allow_null=True
    )
    
    class Meta:
        model = SystemEvent
        fields = (
            'id', 'event_type', 'severity', 'message', 'details',
            'triggered_by', 'triggered_by_username', 'timestamp'
        )
        read_only_fields = ('id', 'timestamp')


class BackupSerializer(serializers.ModelSerializer):
    """Serializer for backup records"""
    triggered_by_username = serializers.CharField(
        source='triggered_by.username', 
        read_only=True, 
        allow_null=True
    )
    
    class Meta:
        model = Backup
        fields = (
            'id', 'name', 'description', 'status', 'file_path', 
            'file_size', 'triggered_by', 'triggered_by_username',
            'started_at', 'completed_at', 'error_message'
        )
        read_only_fields = (
            'id', 'status', 'file_path', 'file_size', 
            'started_at', 'completed_at', 'error_message'
        )


class BackupCreateSerializer(serializers.Serializer):
    """Serializer for creating backups"""
    name = serializers.CharField(required=True, max_length=200)
    description = serializers.CharField(required=False, allow_blank=True)


class SecurityAlertSerializer(serializers.ModelSerializer):
    """Serializer for security alerts"""
    username = serializers.CharField(source='user.username', read_only=True, allow_null=True)
    resolved_by_username = serializers.CharField(
        source='resolved_by.username', 
        read_only=True, 
        allow_null=True
    )
    
    class Meta:
        model = SecurityAlert
        fields = (
            'id', 'alert_type', 'severity', 'title', 'message', 'details',
            'user', 'username', 'ip_address', 'is_resolved', 
            'resolved_by', 'resolved_by_username', 'resolved_at',
            'resolution_notes', 'created_at'
        )
        read_only_fields = (
            'id', 'created_at', 'resolved_at', 'resolved_by'
        )

