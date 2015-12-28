"""
Serializers for data manipulated by the credentials service APIs.
"""
from rest_framework import serializers

from credentials.apps.credentials.models import (
    CourseCertificate, ProgramCertificate,
    UserCredential, UserCredentialAttribute
)


class CredentialRelatedField(serializers.RelatedField):  # pylint: disable=abstract-method
    """
    A custom field to use for the user credential generic relationship.
    """

    def to_representation(self, value):
        """
        Serialize objects to a according to model content-type.
        """
        credential = {
            'credential_id': value.id
        }
        if isinstance(value, ProgramCertificate):
            return credential.update({
                'program_id': value.program_id,
            })
        elif isinstance(value, CourseCertificate):
            return credential.update({
                'course_id': value.course_id,
                'certificate_type': value.certificate_type
            })


class UserCredentialAttributeSerializer(serializers.ModelSerializer):
    """ Serializer for CredentialAttribute objects """

    class Meta(object):
        model = UserCredentialAttribute
        fields = ('namespace', 'name', 'value')


class UserCredentialSerializer(serializers.ModelSerializer):
    """ Serializer for User Credential objects. """

    credential = CredentialRelatedField(read_only='True')
    attributes = UserCredentialAttributeSerializer(many=True, read_only=True)

    class Meta(object):
        model = UserCredential
        include = ('credential', 'attributes', )
        exclude = ('credential_content_type', 'credential_id')
