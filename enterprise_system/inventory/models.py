from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from decimal import Decimal


# ============================================================================
# Inventory & Resource Management (DAC - Discretionary Access Control)
# ============================================================================

class InventoryItem(models.Model):
    """Inventory items with DAC - owner controls access"""
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)
    quantity = models.IntegerField(default=0)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    location = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=100, blank=True)
    
    # DAC: Owner controls access
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='owned_inventory_items',
        help_text="Resource owner who controls access"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} (Owner: {self.owner.username})"
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', 'is_active']),
            models.Index(fields=['department', 'category']),
            models.Index(fields=['created_at']),
        ]


class ResourcePermission(models.Model):
    """DAC permissions - resource owners grant/revoke access"""
    PERMISSION_TYPES = [
        ('read', 'Read'),
        ('write', 'Write'),
        ('delete', 'Delete'),
        ('share', 'Share'),
    ]
    
    resource = models.ForeignKey(
        InventoryItem, 
        on_delete=models.CASCADE, 
        related_name='permissions',
        help_text="The inventory item/resource"
    )
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='resource_permissions',
        help_text="User granted permission"
    )
    permission_type = models.CharField(
        max_length=20, 
        choices=PERMISSION_TYPES,
        help_text="Type of permission granted"
    )
    
    # Grant details
    granted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='permissions_granted',
        help_text="Resource owner who granted this permission"
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Optional expiration")
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.permission_type} on {self.resource.name}"
    
    def is_expired(self):
        """Check if permission has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    class Meta:
        unique_together = [['resource', 'user', 'permission_type']]
        ordering = ['-granted_at']
        indexes = [
            models.Index(fields=['resource', 'user', 'is_active']),
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
        ]


class PermissionLog(models.Model):
    """Audit log for access and permission changes (DAC)"""
    ACTION_TYPES = [
        ('access', 'Resource Access'),
        ('grant', 'Permission Granted'),
        ('revoke', 'Permission Revoked'),
        ('modify', 'Permission Modified'),
        ('create', 'Resource Created'),
        ('update', 'Resource Updated'),
        ('delete', 'Resource Deleted'),
    ]
    
    resource = models.ForeignKey(
        InventoryItem, 
        on_delete=models.CASCADE, 
        related_name='permission_logs'
    )
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='permission_log_entries'
    )
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    details = models.JSONField(default=dict, help_text="Additional action details")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.action} on {self.resource.name} by {self.user.username if self.user else 'System'}"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['resource', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]


# ============================================================================
# Procurement & Rule-Based Access Control (RuBAC)
# ============================================================================

class PurchaseOrder(models.Model):
    """Purchase orders with conditional approval rules based on cost and role"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('pending_approval', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
    ]
    
    po_number = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    vendor = models.CharField(max_length=200)
    
    # Requester
    requested_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='purchase_orders'
    )
    department = models.CharField(max_length=100, blank=True)
    
    # Approval workflow
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        blank=True,
        related_name='approved_purchase_orders'
    )
    approval_notes = models.TextField(blank=True)
    
    # Timestamps
    requested_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    required_approval_date = models.DateTimeField(null=True, blank=True)
    
    # RuBAC: Business rules
    requires_approval = models.BooleanField(default=True)
    approval_rule_applied = models.CharField(max_length=200, blank=True, help_text="Which rule triggered approval requirement")
    
    def __str__(self):
        return f"PO {self.po_number} - {self.status} - ${self.total_amount}"
    
    def _apply_approval_rules(self):
        """Apply RuBAC approval rules based on amount, role, and time"""
        from django.db.models import Q
        
        # Get active approval rules ordered by priority
        rules = ApprovalRule.objects.filter(is_active=True).order_by('-priority')
        
        for rule in rules:
            # Check amount thresholds
            if rule.min_amount and self.total_amount < rule.min_amount:
                continue
            if rule.max_amount and self.total_amount > rule.max_amount:
                continue
            
            # Check department
            if rule.required_departments and self.department not in rule.required_departments:
                continue
            
            # Check working hours
            if rule.working_hours_only:
                now = timezone.now()
                current_time = now.time()
                if rule.working_hours_start and rule.working_hours_end:
                    if not (rule.working_hours_start <= current_time <= rule.working_hours_end):
                        # Outside working hours - requires approval
                        self.requires_approval = True
                        self.status = 'pending_approval'
                        self.approval_rule_applied = f"{rule.name} (working hours restriction)"
                        return
            
            # Rule matched - requires approval
            self.requires_approval = True
            self.status = 'pending_approval'
            self.approval_rule_applied = rule.name
            return
        
        # No rules matched - auto-approve if amount is below threshold
        # Default: require approval for amounts > $1000
        if self.total_amount > Decimal('1000.00'):
            self.requires_approval = True
            self.status = 'pending_approval'
            self.approval_rule_applied = "Default rule (amount > $1000)"
        else:
            self.requires_approval = False
            self.status = 'approved'
            self.approval_rule_applied = "Auto-approved (below threshold)"
    
    class Meta:
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['status', 'requested_at']),
            models.Index(fields=['requested_by', 'status']),
            models.Index(fields=['total_amount']),
        ]


class ApprovalRule(models.Model):
    """Business rules for procurement approval (RuBAC)"""
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    
    # Rule conditions
    min_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        null=True, 
        blank=True,
        help_text="Minimum amount threshold"
    )
    max_amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        null=True, 
        blank=True,
        help_text="Maximum amount threshold"
    )
    required_roles = models.JSONField(
        default=list, 
        help_text="Roles that can approve (empty = any admin)"
    )
    required_departments = models.JSONField(
        default=list, 
        help_text="Departments this rule applies to (empty = all)"
    )
    
    # Time-based rules
    working_hours_only = models.BooleanField(
        default=False, 
        help_text="Require approval only during working hours"
    )
    working_hours_start = models.TimeField(null=True, blank=True, default='09:00')
    working_hours_end = models.TimeField(null=True, blank=True, default='17:00')
    
    is_active = models.BooleanField(default=True)
    priority = models.IntegerField(default=0, help_text="Higher priority rules evaluated first")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['-priority', 'name']
        indexes = [
            models.Index(fields=['is_active', 'priority']),
        ]


# ============================================================================
# Audit, Logging & System Health
# ============================================================================

class UserActivityLog(models.Model):
    """User activity logs for audit trail"""
    ACTION_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('create', 'Create'),
        ('read', 'Read'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('share', 'Share'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('export', 'Export'),
        ('import', 'Import'),
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='activity_logs'
    )
    username = models.CharField(max_length=150, help_text="Store username in case user is deleted")
    action = models.CharField(max_length=50, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=100, blank=True, help_text="Type of resource accessed")
    resource_id = models.CharField(max_length=255, blank=True, help_text="ID of resource accessed")
    details = models.JSONField(default=dict, help_text="Additional action details")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.username} - {self.action} at {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]


class SystemEvent(models.Model):
    """System-level events for audit and monitoring"""
    EVENT_TYPES = [
        ('startup', 'System Startup'),
        ('shutdown', 'System Shutdown'),
        ('config_change', 'Configuration Change'),
        ('security_event', 'Security Event'),
        ('backup', 'Backup'),
        ('restore', 'Restore'),
        ('maintenance', 'Maintenance'),
        ('error', 'Error'),
        ('warning', 'Warning'),
    ]
    
    SEVERITY_LEVELS = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='info')
    message = models.TextField()
    details = models.JSONField(default=dict, help_text="Additional event details")
    triggered_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        blank=True,
        related_name='system_events_triggered'
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.event_type} - {self.severity} at {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]


class Backup(models.Model):
    """System backup records"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True, help_text="Size in bytes")
    triggered_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='backups_triggered'
    )
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.name} - {self.status}"
    
    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['status', 'started_at']),
            models.Index(fields=['triggered_by', 'started_at']),
        ]


class SecurityAlert(models.Model):
    """Security alerts and anomalies"""
    ALERT_TYPES = [
        ('failed_login', 'Failed Login Attempts'),
        ('unauthorized_access', 'Unauthorized Access Attempt'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('policy_violation', 'Policy Violation'),
        ('data_breach', 'Data Breach'),
        ('system_compromise', 'System Compromise'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='medium')
    title = models.CharField(max_length=200)
    message = models.TextField()
    details = models.JSONField(default=dict, help_text="Additional alert details")
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        blank=True,
        related_name='security_alerts'
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        blank=True,
        related_name='alerts_resolved'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.title}"
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type', 'severity', 'is_resolved']),
            models.Index(fields=['is_resolved', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]
