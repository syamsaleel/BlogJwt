from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsAdminUserOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        # Allow read-only permissions to any user (authenticated or anonymous)
        if request.method in SAFE_METHODS:
            return True

        # Allow full access to admins
        return request.user.is_admin

        #return request.user and request.user.is_authenticated and request.user.is_admin
