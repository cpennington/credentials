"""
Serializers for data manipulated by the credentials service APIs.
"""
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from credentials.apps.api.accreditor import Accreditor
from credentials.apps.credentials.models import (
    CourseCertificate, ProgramCertificate,
    UserCredential, UserCredentialAttribute
)


class CredentialField(serializers.Field):
    """
    A custom field to use for the user credential generic relationship.
    """

    def to_internal_value(self, data):
        # TODO Raise ValidationError if the provided data is invalid
        if 'program_id' in data:
            return ProgramCertificate.objects.get(program_id=data['program_id'])
        elif 'course_id' in data:
            return CourseCertificate.objects.get(course_id=data['course_id'], certificate_type=data['certificate_type'])
        else:
            # TODO Provide a better exception message.
            raise ValidationError

    def to_representation(self, value):
        """
        Serialize objects to a according to model content-type.
        """
        credential = {
            'credential_id': value.id
        }
        if isinstance(value, ProgramCertificate):
            credential.update({
                'program_id': value.program_id,
            })
        elif isinstance(value, CourseCertificate):
            credential.update({
                'course_id': value.course_id,
                'certificate_type': value.certificate_type
            })

        return credential


class UserCredentialAttributeSerializer(serializers.ModelSerializer):
    """ Serializer for CredentialAttribute objects """

    class Meta(object):
        model = UserCredentialAttribute
        fields = ('namespace', 'name', 'value')


class UserCredentialSerializer(serializers.ModelSerializer):
    """ Serializer for User Credential objects. """

    credential = CredentialField()
    attributes = UserCredentialAttributeSerializer(many=True)

    class Meta(object):
        model = UserCredential
        exclude = ('credential_content_type', 'credential_id')
        read_only_fields = ('credential', 'username', 'download_url', 'uuid')


class UserCredentialCreationSerializer(serializers.ModelSerializer):
    """ Serializer used to create/update UserCredential objects. """
    credential = CredentialField()
    attributes = UserCredentialAttributeSerializer(many=True)

    def issue_credential(self, validated_data):
        """
        Issue a new credential.

        Args:
            validated_data (dict): Input data specifying the credential type, recipient, and attributes.

        Returns:
            AbstractCredential
        """
        accreditor = Accreditor()
        credential = validated_data.pop('credential')
        credential_type = credential.credential_type_slug
        username = validated_data.pop('username')

        # All remaining data can be lumped into the kwargs attribute, along with
        # the credential identifier.
        kwargs = validated_data

        # TODO Given that we have the credential here, we might want to get rid of the Accreditor. Instead, we
        # could use the factory pattern to get an issuer based on typeof(credential).
        kwargs.update(CredentialField().to_representation(credential))

        return accreditor.issue_credential(credential_type, username, **kwargs)

    def create(self, validated_data):
        return self.issue_credential(validated_data)

    def update(self, instance, validated_data):
        return self.issue_credential(validated_data)

    class Meta(object):
        model = UserCredential
        exclude = ('credential_content_type', 'credential_id')
