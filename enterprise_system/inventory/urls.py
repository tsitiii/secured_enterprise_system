from django.urls import path
from . import views

urlpatterns = [

    # Inventory & Resource Management (DAC)
    path('inventory/items', views.InventoryItemListView.as_view(), name='inventory-items'),
    path('inventory/share', views.ResourceShareView.as_view(), name='inventory-share'),
    path('inventory/permissions-log/<int:item_id>', views.PermissionLogListView.as_view(), name='permissions-log'),
    
    # Procurement & Rule-Based Access Control (RuBAC)
    path('procurement/purchase-orders', views.PurchaseOrderCreateView.as_view(), name='purchase-orders'),
    path('procurement/pending-approvals', views.PendingApprovalsView.as_view(), name='pending-approvals'),
    
    # Audit, Logging & System Health
    path('admin/logs/user-activity', views.UserActivityLogListView.as_view(), name='user-activity-logs'),
    path('admin/logs/system-events', views.SystemEventListView.as_view(), name='system-events'),
    path('admin/backup/trigger', views.BackupTriggerView.as_view(), name='backup-trigger'),
    path('admin/alerts', views.SecurityAlertsListView.as_view(), name='security-alerts'),

]

