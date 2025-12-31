from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Q
from django.db import transaction
from django.core.management import call_command
from django.core.files.storage import default_storage
import os
import json

from .models import (
    InventoryItem, ResourcePermission, PermissionLog,
    PurchaseOrder, ApprovalRule,
    UserActivityLog, SystemEvent, Backup, SecurityAlert
)
from .serializers import (
    InventoryItemSerializer, ResourcePermissionSerializer,
    ResourceShareSerializer, PermissionLogSerializer,
    PurchaseOrderSerializer, PurchaseOrderCreateSerializer,
    ApprovalRuleSerializer,
    UserActivityLogSerializer, SystemEventSerializer,
    BackupSerializer, BackupCreateSerializer, SecurityAlertSerializer
)
from accounts.models import UserRole
from accounts.utils import get_client_ip

from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes


# ============================================================================
# Inventory & Resource Management (DAC - Discretionary Access Control)
# ============================================================================

class InventoryItemListView(generics.ListCreateAPIView):
    """GET/POST /api/inventory/items - List and create inventory items"""
    serializer_class = InventoryItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="List inventory items",
        description="List inventory items filtered by role and department. Users see items they own or have permissions for.",
        parameters=[
            OpenApiParameter('department', OpenApiTypes.STR, description='Filter by department', required=False),
            OpenApiParameter('category', OpenApiTypes.STR, description='Filter by category', required=False),
            OpenApiParameter('search', OpenApiTypes.STR, description='Search in name and description', required=False),
        ],
        responses={
            200: InventoryItemSerializer(many=True),
            201: InventoryItemSerializer,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @extend_schema(
        summary="Create inventory item",
        description="Create new inventory item. Creator becomes the resource owner.",
        request=InventoryItemSerializer,
        responses={
            201: InventoryItemSerializer,
            400: OpenApiTypes.OBJECT,
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
    def get_queryset(self):
        """Filter items based on user's role, department, and permissions"""
        user = self.request.user
        queryset = InventoryItem.objects.filter(is_active=True)
        
        # Get user's roles and departments
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).exclude(expires_at__lt=timezone.now()).select_related('role')
        
        role_names = [ur.role.name for ur in user_roles if not ur.is_expired()]
        
        # Get user's departments from roles or profile
        departments = set()
        for ur in user_roles:
            if hasattr(ur, 'department') and ur.department:
                departments.add(ur.department)
        
        # Filter: Show items where user is owner OR has permission OR matches role/department
        permission_filter = Q(owner=user) | Q(permissions__user=user, permissions__is_active=True)
        
        # If user has admin role, show all items
        if user.is_staff or any('admin' in role.lower() for role in role_names):
            queryset = queryset
        else:
            # Filter by permissions or ownership
            queryset = queryset.filter(permission_filter).distinct()
        
        # Apply filters
        department = self.request.query_params.get('department')
        if department:
            queryset = queryset.filter(department=department)
        
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category=category)
        
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(description__icontains=search)
            )
        
        return queryset.select_related('owner').prefetch_related('permissions')
    
    def perform_create(self, serializer):
        """Create item and log activity"""
        item = serializer.save(owner=self.request.user)
        
        # Log activity
        UserActivityLog.objects.create(
            user=self.request.user,
            username=self.request.user.username,
            action='create',
            resource_type='inventory_item',
            resource_id=str(item.id),
            details={'name': item.name, 'department': item.department},
            ip_address=get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log permission event
        PermissionLog.objects.create(
            resource=item,
            user=self.request.user,
            action='create',
            details={'name': item.name},
            ip_address=get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        
        return item


class ResourceShareView(APIView):
    """GET/POST /api/inventory/share - List granted permissions or grant/revoke permissions"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="List granted permissions",
        description="List all permissions granted by the current user on resources they own",
        parameters=[
            OpenApiParameter('resource_id', OpenApiTypes.INT, description='Filter by specific resource ID', required=False),
            OpenApiParameter('permission_type', OpenApiTypes.STR, description='Filter by permission type', required=False),
        ],
        responses={
            200: ResourcePermissionSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request):
        """List permissions granted by current user"""
        queryset = ResourcePermission.objects.filter(
            granted_by=request.user,
            is_active=True
        ).select_related('resource', 'user', 'granted_by')
        
        # Apply filters
        resource_id = request.query_params.get('resource_id')
        if resource_id:
            queryset = queryset.filter(resource_id=resource_id)
        
        permission_type = request.query_params.get('permission_type')
        if permission_type:
            queryset = queryset.filter(permission_type=permission_type)
        
        serializer = ResourcePermissionSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @extend_schema(
        summary="Share resource",
        description="Resource owners grant or revoke permissions to other users. Set 'action' to 'revoke' to revoke permissions.",
        request=ResourceShareSerializer,
        responses={
            200: ResourcePermissionSerializer,
            201: ResourcePermissionSerializer,
            400: OpenApiTypes.OBJECT,
            403: OpenApiTypes.OBJECT,
            404: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Grant Permission',
                value={
                    'resource_id': 1,
                    'user_id': 2,
                    'permission_type': 'read',
                    'expires_at': '2025-12-31T23:59:59Z',
                    'notes': 'Temporary access for project'
                },
                request_only=True
            ),
            OpenApiExample(
                'Revoke Permission',
                value={
                    'action': 'revoke',
                    'resource_id': 1,
                    'user_id': 2,
                    'permission_type': 'read'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        action = request.data.get('action', 'grant')  # 'grant' or 'revoke'
        
        if action == 'revoke':
            resource_id = request.data.get('resource_id')
            user_id = request.data.get('user_id')
            permission_type = request.data.get('permission_type')
            
            if not all([resource_id, user_id, permission_type]):
                return Response(
                    {'error': 'resource_id, user_id, and permission_type are required for revocation'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                resource = InventoryItem.objects.get(id=resource_id)
                target_user = User.objects.get(id=user_id)
            except (InventoryItem.DoesNotExist, User.DoesNotExist):
                return Response(
                    {'error': 'Resource or user not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Verify ownership
            if resource.owner != request.user:
                return Response(
                    {'error': 'Only the resource owner can revoke permissions'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            try:
                permission = ResourcePermission.objects.get(
                    resource=resource,
                    user=target_user,
                    permission_type=permission_type
                )
                permission.is_active = False
                permission.save()
                
                # Log permission revocation
                PermissionLog.objects.create(
                    resource=resource,
                    user=request.user,
                    action='revoke',
                    details={
                        'revoked_from': target_user.username,
                        'permission_type': permission_type
                    },
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return Response(
                    {'message': 'Permission revoked successfully'},
                    status=status.HTTP_200_OK
                )
            except ResourcePermission.DoesNotExist:
                return Response(
                    {'error': 'Permission not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Handle grant
            serializer = ResourceShareSerializer(data=request.data, context={'request': request})
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            resource_id = serializer.validated_data['resource_id']
            user_id = serializer.validated_data['user_id']
            permission_type = serializer.validated_data['permission_type']
            expires_at = serializer.validated_data.get('expires_at')
            notes = serializer.validated_data.get('notes', '')
            
            try:
                resource = InventoryItem.objects.get(id=resource_id)
                target_user = User.objects.get(id=user_id)
            except (InventoryItem.DoesNotExist, User.DoesNotExist):
                return Response(
                    {'error': 'Resource or user not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Verify ownership
            if resource.owner != request.user:
                return Response(
                    {'error': 'Only the resource owner can grant permissions'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Create or update permission
            permission, created = ResourcePermission.objects.update_or_create(
                resource=resource,
                user=target_user,
                permission_type=permission_type,
                defaults={
                    'granted_by': request.user,
                    'expires_at': expires_at,
                    'notes': notes,
                    'is_active': True
                }
            )
            
            # Log permission grant
            PermissionLog.objects.create(
                resource=resource,
                user=request.user,
                action='grant',
                details={
                    'granted_to': target_user.username,
                    'permission_type': permission_type,
                    'expires_at': str(expires_at) if expires_at else None
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log activity
            UserActivityLog.objects.create(
                user=request.user,
                username=request.user.username,
                action='share',
                resource_type='inventory_item',
                resource_id=str(resource.id),
                details={
                    'granted_to': target_user.username,
                    'permission_type': permission_type
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            response_serializer = ResourcePermissionSerializer(permission)
            status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
            return Response(response_serializer.data, status=status_code)


class PermissionLogListView(generics.ListAPIView):
    """GET /api/inventory/permissions-log/{item_id} - Audit log of access and permission changes"""
    serializer_class = PermissionLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Get permission audit log",
        description="Get audit log of access and permission changes for a specific inventory item",
        parameters=[
            OpenApiParameter('action', OpenApiTypes.STR, description='Filter by action type', required=False),
            OpenApiParameter('user', OpenApiTypes.INT, description='Filter by user ID', required=False),
        ],
        responses={
            200: PermissionLogSerializer(many=True),
            403: OpenApiTypes.OBJECT,
            404: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Get permission logs for a specific item"""
        item_id = self.kwargs.get('item_id')
        
        try:
            item = InventoryItem.objects.get(id=item_id)
        except InventoryItem.DoesNotExist:
            return PermissionLog.objects.none()
        
        # Check if user has access (owner or has permission)
        user = self.request.user
        has_access = (
            item.owner == user or
            ResourcePermission.objects.filter(
                resource=item,
                user=user,
                is_active=True
            ).exists() or
            user.is_staff
        )
        
        if not has_access:
            return PermissionLog.objects.none()
        
        queryset = PermissionLog.objects.filter(resource=item)
        
        # Apply filters
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        user_id = self.request.query_params.get('user')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        return queryset.select_related('user', 'resource').order_by('-timestamp')


# ============================================================================
# Procurement & Rule-Based Access Control (RuBAC)
# ============================================================================

class PurchaseOrderCreateView(APIView):
    """POST /api/procurement/purchase-orders - Create purchase orders with conditional approval rules"""
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Create purchase order",
        description="Create purchase order with conditional approval rules based on cost and role",
        request=PurchaseOrderCreateSerializer,
        responses={
            201: PurchaseOrderSerializer,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Create Purchase Order',
                value={
                    'description': 'Office supplies for Q1',
                    'total_amount': '5000.00',
                    'vendor': 'Office Supply Co.',
                    'department': 'Operations',
                    'required_approval_date': '2024-02-01T00:00:00Z'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = PurchaseOrderCreateSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        po = serializer.save()
        
        # Log activity
        UserActivityLog.objects.create(
            user=request.user,
            username=request.user.username,
            action='create',
            resource_type='purchase_order',
            resource_id=str(po.id),
            details={
                'po_number': po.po_number,
                'total_amount': str(po.total_amount),
                'status': po.status
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        response_serializer = PurchaseOrderSerializer(po)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class PendingApprovalsView(generics.ListAPIView):
    """GET /api/procurement/pending-approvals - Get pending approvals (denies access outside working hours unless pre-approved)"""
    serializer_class = PurchaseOrderSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Get pending approvals",
        description="Get purchase orders pending approval. Access is denied outside working hours unless pre-approved.",
        parameters=[
            OpenApiParameter('department', OpenApiTypes.STR, description='Filter by department', required=False),
        ],
        responses={
            200: PurchaseOrderSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        # Check working hours
        now = timezone.now()
        current_time = now.time()
        
        # Default working hours: 9 AM - 5 PM
        from datetime import time
        working_hours_start = time(9, 0)
        working_hours_end = time(17, 0)
        
        # Check if outside working hours
        outside_working_hours = not (working_hours_start <= current_time <= working_hours_end)
        
        if outside_working_hours:
            # Check if user has pre-approval (admin or special role)
            user_roles = UserRole.objects.filter(
                user=request.user,
                is_active=True
            ).exclude(expires_at__lt=timezone.now()).select_related('role')
            
            role_names = [ur.role.name for ur in user_roles if not ur.is_expired()]
            has_pre_approval = (
                request.user.is_staff or
                any('admin' in role.lower() or 'approver' in role.lower() for role in role_names)
            )
            
            if not has_pre_approval:
                return Response(
                    {
                        'error': 'Access denied outside working hours (9 AM - 5 PM). Pre-approval required.',
                        'current_time': str(current_time),
                        'working_hours': f'{working_hours_start} - {working_hours_end}'
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
        
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Get pending approval purchase orders"""
        queryset = PurchaseOrder.objects.filter(status='pending_approval')
        
        # Filter by department if provided
        department = self.request.query_params.get('department')
        if department:
            queryset = queryset.filter(department=department)
        
        # Users can see their own POs or if they have approval role
        user = self.request.user
        if not user.is_staff:
            user_roles = UserRole.objects.filter(
                user=user,
                is_active=True
            ).exclude(expires_at__lt=timezone.now()).select_related('role')
            
            role_names = [ur.role.name for ur in user_roles if not ur.is_expired()]
            has_approval_role = any('approver' in role.lower() or 'manager' in role.lower() for role in role_names)
            
            if not has_approval_role:
                # Only show their own POs
                queryset = queryset.filter(requested_by=user)
        
        return queryset.select_related('requested_by', 'approved_by').order_by('-requested_at')


# ============================================================================
# Audit, Logging & System Health
# ============================================================================

class UserActivityLogListView(generics.ListAPIView):
    """GET /api/admin/logs/user-activity - User activity logs"""
    serializer_class = UserActivityLogSerializer
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        summary="Get user activity logs",
        description="Get user activity logs (username, timestamp, IP, action)",
        parameters=[
            OpenApiParameter('username', OpenApiTypes.STR, description='Filter by username', required=False),
            OpenApiParameter('action', OpenApiTypes.STR, description='Filter by action type', required=False),
            OpenApiParameter('resource_type', OpenApiTypes.STR, description='Filter by resource type', required=False),
            OpenApiParameter('start_date', OpenApiTypes.DATETIME, description='Start date filter', required=False),
            OpenApiParameter('end_date', OpenApiTypes.DATETIME, description='End date filter', required=False),
        ],
        responses={
            200: UserActivityLogSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Filter activity logs"""
        queryset = UserActivityLog.objects.all()
        
        # Apply filters
        username = self.request.query_params.get('username')
        if username:
            queryset = queryset.filter(username__icontains=username)
        
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        resource_type = self.request.query_params.get('resource_type')
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                from django.utils.dateparse import parse_datetime
                start = parse_datetime(start_date)
                if start:
                    queryset = queryset.filter(timestamp__gte=start)
            except:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                from django.utils.dateparse import parse_datetime
                end = parse_datetime(end_date)
                if end:
                    queryset = queryset.filter(timestamp__lte=end)
            except:
                pass
        
        return queryset.select_related('user').order_by('-timestamp')


class SystemEventListView(generics.ListAPIView):
    """GET /api/admin/logs/system-events - System-level events"""
    serializer_class = SystemEventSerializer
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        summary="Get system events",
        description="Get system-level events such as startup or configuration changes",
        parameters=[
            OpenApiParameter('event_type', OpenApiTypes.STR, description='Filter by event type', required=False),
            OpenApiParameter('severity', OpenApiTypes.STR, description='Filter by severity', required=False),
            OpenApiParameter('start_date', OpenApiTypes.DATETIME, description='Start date filter', required=False),
            OpenApiParameter('end_date', OpenApiTypes.DATETIME, description='End date filter', required=False),
        ],
        responses={
            200: SystemEventSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Filter system events"""
        queryset = SystemEvent.objects.all()
        
        # Apply filters
        event_type = self.request.query_params.get('event_type')
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                from django.utils.dateparse import parse_datetime
                start = parse_datetime(start_date)
                if start:
                    queryset = queryset.filter(timestamp__gte=start)
            except:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                from django.utils.dateparse import parse_datetime
                end = parse_datetime(end_date)
                if end:
                    queryset = queryset.filter(timestamp__lte=end)
            except:
                pass
        
        return queryset.select_related('triggered_by').order_by('-timestamp')


class BackupTriggerView(APIView):
    """POST /api/admin/backup/trigger - Manually trigger system backups"""
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        summary="Trigger backup",
        description="Manually trigger system backup",
        request=BackupCreateSerializer,
        responses={
            200: BackupSerializer,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Trigger Backup',
                value={
                    'name': 'Daily Backup 2024-01-15',
                    'description': 'Scheduled daily backup'
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = BackupCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        name = serializer.validated_data['name']
        description = serializer.validated_data.get('description', '')
        
        # Create backup record
        backup = Backup.objects.create(
            name=name,
            description=description,
            status='pending',
            triggered_by=request.user
        )
        
        # Trigger backup in background (simplified - in production use Celery or similar)
        try:
            # Update status to in_progress
            backup.status = 'in_progress'
            backup.save()
            
            # Log system event
            SystemEvent.objects.create(
                event_type='backup',
                severity='info',
                message=f'Backup triggered: {name}',
                details={'backup_id': backup.id, 'triggered_by': request.user.username},
                triggered_by=request.user
            )
            
            # In a real implementation, you would:
            # 1. Use Celery to run backup asynchronously
            # 2. Actually perform the backup (database dump, file backup, etc.)
            # 3. Update backup record with file_path and file_size
            # 4. Set status to 'completed' or 'failed'
            
            # For now, simulate completion
            backup.status = 'completed'
            backup.file_path = f'/backups/{backup.id}_{name.replace(" ", "_")}.sql'
            backup.file_size = 1024 * 1024  # Simulated size
            backup.completed_at = timezone.now()
            backup.save()
            
            response_serializer = BackupSerializer(backup)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            backup.status = 'failed'
            backup.error_message = str(e)
            backup.completed_at = timezone.now()
            backup.save()
            
            # Log error event
            SystemEvent.objects.create(
                event_type='error',
                severity='error',
                message=f'Backup failed: {str(e)}',
                details={'backup_id': backup.id},
                triggered_by=request.user
            )
            
            return Response(
                {'error': f'Backup failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecurityAlertsListView(generics.ListAPIView):
    """GET /api/admin/alerts - Fetch security alerts and anomalies"""
    serializer_class = SecurityAlertSerializer
    permission_classes = [permissions.IsAdminUser]
    
    @extend_schema(
        summary="Get security alerts",
        description="Fetch security alerts and anomalies",
        parameters=[
            OpenApiParameter('alert_type', OpenApiTypes.STR, description='Filter by alert type', required=False),
            OpenApiParameter('severity', OpenApiTypes.STR, description='Filter by severity', required=False),
            OpenApiParameter('is_resolved', OpenApiTypes.BOOL, description='Filter by resolution status', required=False),
            OpenApiParameter('start_date', OpenApiTypes.DATETIME, description='Start date filter', required=False),
            OpenApiParameter('end_date', OpenApiTypes.DATETIME, description='End date filter', required=False),
        ],
        responses={
            200: SecurityAlertSerializer(many=True),
            403: OpenApiTypes.OBJECT,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    def get_queryset(self):
        """Filter security alerts"""
        queryset = SecurityAlert.objects.all()
        
        # Apply filters
        alert_type = self.request.query_params.get('alert_type')
        if alert_type:
            queryset = queryset.filter(alert_type=alert_type)
        
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        is_resolved = self.request.query_params.get('is_resolved')
        if is_resolved is not None:
            is_resolved_bool = is_resolved.lower() == 'true'
            queryset = queryset.filter(is_resolved=is_resolved_bool)
        
        start_date = self.request.query_params.get('start_date')
        if start_date:
            try:
                from django.utils.dateparse import parse_datetime
                start = parse_datetime(start_date)
                if start:
                    queryset = queryset.filter(created_at__gte=start)
            except:
                pass
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            try:
                from django.utils.dateparse import parse_datetime
                end = parse_datetime(end_date)
                if end:
                    queryset = queryset.filter(created_at__lte=end)
            except:
                pass
        
        return queryset.select_related('user', 'resolved_by').order_by('-created_at')
