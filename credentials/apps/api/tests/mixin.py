"""Mixin class for authentication."""
from django.contrib.auth.models import Permission
from rest_framework.test import APITestCase


class AuthClientMixin(APITestCase):
    """Mixin useful for getting APIClient objects in tests."""

    def get_api_client(self, user, permission_code=None):
        """
        Helper for concisely obtaining a `rest_framework.test.APIClient` instance,
        authenticated with a user having specific model level permissions.

        Arguments:
            user (User): User object for which permissions are required.
            permission_code (string): Permission codename for specific permission

        Returns:
            returns authenticated APIClient object with specific permissions, if no
            permission provided then it will returns default object.
        """
        if permission_code:
            # pylint: disable=maybe-no-member
            user.user_permissions.add(Permission.objects.get(codename=permission_code))
            self.client.force_authenticate(user)

        return self.client
