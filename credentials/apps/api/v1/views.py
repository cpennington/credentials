"""
Credentials service API views (v1).
"""
import logging

from rest_framework import filters
from rest_framework import viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import DjangoModelPermissionsOrAnonReadOnly

from credentials.apps.api.serializers import UserCredentialSerializer, UserCredentialCreationSerializer
from credentials.apps.credentials.models import UserCredential

log = logging.getLogger(__name__)


class UserCredentialViewSet(viewsets.ModelViewSet):
    """ UserCredentials endpoints. """

    queryset = UserCredential.objects.all()
    filter_backends = (filters.DjangoFilterBackend,)
    filter_fields = ('username', 'status')
    serializer_class = UserCredentialSerializer
    permission_classes = (DjangoModelPermissionsOrAnonReadOnly,)

    def get_serializer_class(self):
        # Use a custom serializer for the create (POST) action. This serializer knows how to create
        # credentials of the appropriate type.
        if self.request.method == 'POST':
            return UserCredentialCreationSerializer
        else:
            return super(UserCredentialViewSet, self).get_serializer_class()

    def list(self, request, *args, **kwargs):
        if not self.request.query_params.get('username'):
            raise ValidationError({'error': 'Username is required for filtering user_credentials.'})

        return super(UserCredentialViewSet, self).list(request, *args, **kwargs)  # pylint: disable=maybe-no-member
