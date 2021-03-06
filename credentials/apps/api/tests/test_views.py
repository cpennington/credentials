"""
Tests for credentials service views.
"""
from __future__ import unicode_literals
import json

import ddt
from django.contrib.auth.models import Permission
from django.core.urlresolvers import reverse
from rest_framework.test import APITestCase, APIRequestFactory
from testfixtures import LogCapture

from credentials.apps.api.serializers import UserCredentialSerializer
from credentials.apps.api.tests import factories
from credentials.apps.credentials.models import UserCredential


JSON_CONTENT_TYPE = 'application/json'
LOGGER_NAME = 'credentials.apps.credentials.issuers'
LOGGER_NAME_SERIALIZER = 'credentials.apps.api.serializers'


@ddt.ddt
class UserCredentialViewSetTests(APITestCase):
    """ Tests for GenerateCredentialView. """

    list_path = reverse("api:v1:usercredential-list")

    def setUp(self):
        super(UserCredentialViewSetTests, self).setUp()

        self.user = factories.UserFactory()
        self.client.force_authenticate(self.user)  # pylint: disable=no-member

        self.program_cert = factories.ProgramCertificateFactory()
        self.program_id = self.program_cert.program_id
        self.user_credential = factories.UserCredentialFactory.create(credential=self.program_cert)
        self.user_credential_attribute = factories.UserCredentialAttributeFactory.create(
            user_credential=self.user_credential)
        self.username = "test_user"
        self.request = APIRequestFactory().get('/')

    def _attempt_update_user_credential(self, data):
        """ Helper method that attempts to patch an existing credential object.

        Arguments:
          data (dict): Data to be converted to JSON and sent to the API.

        Returns:
          Response: HTTP response from the API.
        """
        # pylint: disable=no-member
        self.user.user_permissions.add(Permission.objects.get(codename="change_usercredential"))
        path = reverse("api:v1:usercredential-detail", args=[self.user_credential.id])
        return self.client.patch(path=path, data=json.dumps(data), content_type=JSON_CONTENT_TYPE)

    def test_get(self):
        """ Verify a single user credential is returned. """

        path = reverse("api:v1:usercredential-detail", args=[self.user_credential.id])
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            UserCredentialSerializer(self.user_credential, context={'request': self.request}).data
        )

    def test_list_without_username(self):
        """ Verify a list end point of user credentials will work only with
        username filter. Otherwise it will return 400.
        """
        response = self.client.get(self.list_path)
        self.assertEqual(response.status_code, 400)

    def test_partial_update(self):
        """ Verify that only the 'status' field is updated and other fields
        value remain same.
        """
        data = {
            'id': self.user_credential.id,
            'status': UserCredential.REVOKED,
            'download_url': self.user_credential.download_url + 'test'
        }

        response = self._attempt_update_user_credential(data)
        self.assertEqual(response.status_code, 200)

        user_credential = UserCredential.objects.get(id=self.user_credential.id)
        self.assertEqual(user_credential.status, data["status"])

        self.assertNotEqual(user_credential.download_url, data["download_url"])
        self.assertEqual(user_credential.download_url, self.user_credential.download_url)

    def test_partial_update_authentication(self):
        """ Verify that patch endpoint allows only authorized users to update
        user credential.
        """
        self.client.logout()
        data = {
            "id": self.user_credential.id,
            "download_url": "dummy-url",
        }

        path = reverse("api:v1:usercredential-detail", args=[self.user_credential.id])
        response = self.client.patch(path=path, data=json.dumps(data), content_type=JSON_CONTENT_TYPE)
        self.assertEqual(response.status_code, 401)

    def _attempt_create_user_credentials(self, data):
        """ Helper method that attempts to create user credentials.

        Arguments:
          data (dict): Data to be converted to JSON and sent to the API.

        Returns:
          Response: HTTP response from the API.
        """
        # pylint: disable=no-member
        self.user.user_permissions.add(Permission.objects.get(codename="add_usercredential"))
        path = self.list_path
        return self.client.post(path=path, data=json.dumps(data), content_type=JSON_CONTENT_TYPE)

    @ddt.data(
        ("username", "", "This field may not be blank."),
        ("credential", "", "Credential ID is missing."),
        ("credential", {"program_id": ""}, "Credential ID is missing."),
        ("credential", {"course_id": ""}, "Credential ID is missing."),
    )
    @ddt.unpack
    def test_create_with_empty_fields(self, field_name, value, err_msg):
        """ Verify no UserCredential is created, and HTTP 400 is returned, if
        required fields are missing.
        """
        data = {
            "username": self.username,
            "credential": {"program_id": self.program_id},
            "attributes": [
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                }
            ]
        }
        data.update({field_name: value})
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data.get(field_name),
            [err_msg]
        )

    @ddt.data(
        "username",
        "credential",
        "attributes",
    )
    def test_create_with_missing_fields(self, field_name):
        """ Verify no UserCredential is created, and HTTP 400 is returned, if
        required fields are missing.
        """
        data = {
            "username": self.username,
            "credential": {"program_id": self.program_id},
            "attributes": [
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                }
            ]
        }
        del data[field_name]
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data.get(field_name),
            ['This field is required.']
        )

    def test_create_with_programcertificate(self):
        """ Verify the endpoint supports issuing a new ProgramCertificate credential. """
        program_certificate = factories.ProgramCertificateFactory()
        data = {
            "username": self.username,
            "credential": {
                "program_id": program_certificate.program_id
            },
            "attributes": [
                {
                    "name": self.user_credential_attribute.name,
                    "value": self.user_credential_attribute.value
                },
            ]
        }
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 201)
        user_credential = UserCredential.objects.get(username=self.username)
        self.assertEqual(
            dict(response.data),
            dict(UserCredentialSerializer(user_credential, context={'request': self.request}).data)
        )

    def test_create_authentication(self):
        """ Verify that the create endpoint of user credential does not allow
        the unauthorized users to create a new user credential for the program.
        """
        self.client.logout()
        response = self.client.post(path=self.list_path, data={}, content_type=JSON_CONTENT_TYPE)

        self.assertEqual(response.status_code, 401)

    def test_create_with_duplicate_attributes(self):
        """ Verify no UserCredential is created, and HTTP 400 is returned, if
        there are duplicated attributes.
        """
        data = {
            "username": self.username,
            "credential": {"program_id": self.program_id},
            "attributes": [
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                },
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                },
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                },
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                }
            ]
        }

        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.data, {'attributes': ['Attributes cannot be duplicated.']})

        self.assertEqual(response.status_code, 400)
        self.assertFalse(UserCredential.objects.filter(username=self.username).exists())

    def test_create_with_empty_attributes(self):
        """ Verify no UserCredential is created, and HTTP 400 is returned, if
        there are some attributes are null.
        """
        data = {
            "username": self.username,
            "credential": {"program_id": self.program_id},
            "attributes": [
                {
                    "name": "whitelist_reason",
                    "value": "Reason for whitelisting."
                },
                {
                    "name": "",
                    "value": "Reason for whitelisting."
                }
            ]
        }
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(UserCredential.objects.filter(username=self.username).exists())
        self.assertEqual(
            response.data.get('attributes')[1]['name'][0],
            'This field may not be blank.'
        )

    def test_list_with_username_filter(self):
        """ Verify the list endpoint supports filter data by username."""
        factories.UserCredentialFactory(username="dummy-user")
        response = self.client.get(self.list_path, data={'username': self.user_credential.username})
        self.assertEqual(response.status_code, 200)

        # after filtering it is only one related record
        expected = UserCredentialSerializer(
            self.user_credential, context={'request': self.request}
        ).data

        self.assertEqual(response.data, {'count': 1, 'next': None, 'previous': None, 'results': [expected]})

    def test_list_with_status_filter(self):
        """ Verify the list endpoint supports filtering by status."""
        factories.UserCredentialFactory.create_batch(2, status="revoked", username=self.user_credential.username)
        response = self.client.get(self.list_path, data={'status': self.user_credential.status})
        self.assertEqual(response.status_code, 400)

        # username and status will return the data.
        response = self.client.get(self.list_path,
                                   data={'username': self.user_credential.username, 'status': UserCredential.AWARDED})

        # after filtering it is only one related record
        expected = UserCredentialSerializer(
            self.user_credential, context={'request': self.request}
        ).data

        self.assertEqual(
            response.data,
            {'count': 1, 'next': None, 'previous': None, 'results': [expected]}
        )

    def test_create_with_non_existing_credential(self):
        """ Verify no UserCredential is created, and HTTP 400 is return if credential
        id does not exists in db.
        """
        cred_id = 10
        data = {
            "username": self.username,
            "credential": {
                "program_id": cred_id
            },
            "attributes": [
            ]
        }

        msg = "Credential ID [{cred_id}] for [ProgramCertificate matching query does not exist.]".format(
            cred_id=cred_id
        )

        # Verify log is captured.
        with LogCapture(LOGGER_NAME_SERIALIZER) as l:
            response = self._attempt_create_user_credentials(data)
            l.check((LOGGER_NAME_SERIALIZER, 'ERROR', msg))

        self.assertEqual(response.status_code, 400)

    def test_reissue_the_user_credentials(self):
        """ Verify that, if a user has already been issued a credential, further
        attempts to issue the same credential will NOT create a new credential,
        but its attributes will be updated if provided.
        """
        attributes = [
            {"name": "whitelist_reason", "value": "Reason for whitelisting."},
            {"name": "grade", "value": "0.85"}
        ]

        data = {
            "username": self.username,
            "credential": {
                "program_id": self.program_cert.program_id
            },
            "attributes": attributes
        }

        # issue first credential for the user
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 201)
        self._assert_usercredential_fields(response, self.username, attributes)

        # change the attributes value
        data["attributes"][0]["value"] = "New reason for whitelisting."
        data["attributes"][1]["value"] = "0.8"

        # try to issue credential again for the same user but with different attribute values and
        # test that the existing record for user credential has been updated with new attribute values
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 201)
        self._assert_usercredential_fields(response, self.username, attributes)

    @ddt.data(
        [{"name": "whitelist_reason", "value": "Reason for whitelisting."}],
        [
            {"name": "whitelist_reason", "value": "Reason for whitelisting."},
            {"name": "grade", "value": "0.85"},
        ],
    )
    def test_create_with_duplicate_attrs(self, attributes):
        """ Verify that, if a user has a credential with attributes
        then its values can be updated.
        """
        # create credential with attributes
        user_credential = factories.UserCredentialFactory.create(
            username=self.username,
            credential=self.program_cert
        )
        factories.UserCredentialAttributeFactory(
            user_credential=user_credential, name="whitelist_reason", value="Reason for whitelisting."
        )
        self.assertTrue(user_credential.attributes.exists())

        data = {
            "username": self.username,
            "credential": {
                "program_id": self.program_id
            },
            "attributes": attributes
        }

        # 2nd attempt to create credential with attributes.
        response = self._attempt_create_user_credentials(data)
        self.assertEqual(response.status_code, 201)
        self._assert_usercredential_fields(response, self.username, attributes)

    def _assert_usercredential_fields(self, response, username, expected_attrs):
        """ Verify the fields on a UserCredential object match expectations. """

        user_credential = UserCredential.objects.filter(username=username)
        self.assertEqual(user_credential.count(), 1)
        self.assertEqual(
            dict(response.data),
            dict(UserCredentialSerializer(
                user_credential[0], context={'request': self.request}
            ).data)
        )

        actual_attributes = [{"name": attr.name, "value": attr.value} for attr in user_credential[0].attributes.all()]
        self.assertEqual(actual_attributes, expected_attrs)


class CredentialViewSetTests(APITestCase):
    """ Base Class for ProgramCredentialViewSetTests and CourseCredentialViewSetTests. """

    list_path = None
    user_credential = None

    def setUp(self):
        super(CredentialViewSetTests, self).setUp()

        self.user = factories.UserFactory()
        self.client.force_authenticate(self.user)  # pylint: disable=no-member
        self.request = APIRequestFactory().get('/')

    def assert_list_without_id_filter(self, path, expected):
        """Helper method used for making request and assertions. """
        response = self.client.get(path)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, expected)

    def assert_list_with_id_filter(self, data):
        """Helper method used for making request and assertions. """
        expected = {'count': 1, 'next': None, 'previous': None,
                    'results': [UserCredentialSerializer(self.user_credential, context={'request': self.request}).data]}
        response = self.client.get(self.list_path, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, expected)

    def assert_list_with_status_filter(self, data):
        """Helper method for making request and assertions. """
        expected = {'count': 1, 'next': None, 'previous': None,
                    'results': [UserCredentialSerializer(self.user_credential, context={'request': self.request}).data]}
        response = self.client.get(self.list_path, data, expected)
        self.assertEqual(json.loads(response.content), expected)


class ProgramCredentialViewSetTests(CredentialViewSetTests):
    """ Tests for ProgramCredentialViewSetTests. """

    list_path = reverse("api:v1:programcredential-list")

    def setUp(self):
        super(ProgramCredentialViewSetTests, self).setUp()

        self.program_certificate = factories.ProgramCertificateFactory()
        self.program_id = self.program_certificate.program_id
        self.user_credential = factories.UserCredentialFactory.create(credential=self.program_certificate)
        self.request = APIRequestFactory().get('/')

    def test_list_without_program_id(self):
        """ Verify a list end point of program credentials will work only with
        program_id filter.
        """
        self.assert_list_without_id_filter(path=self.list_path, expected={
            'error': 'A program_id query string parameter is required for filtering program credentials.'
        })

    def test_list_with_program_id_filter(self):
        """ Verify the list endpoint supports filter data by program_id."""
        program_cert = factories.ProgramCertificateFactory(program_id=001)
        factories.UserCredentialFactory.create(credential=program_cert)
        self.assert_list_with_id_filter(data={'program_id': self.program_id})

    def test_list_with_status_filter(self):
        """ Verify the list endpoint supports filtering by status."""
        factories.UserCredentialFactory.create_batch(2, status="revoked", username=self.user_credential.username)
        self.assert_list_with_status_filter(data={'program_id': self.program_id, 'status': UserCredential.AWARDED}, )


class CourseCredentialViewSetTests(CredentialViewSetTests):
    """ Tests for CourseCredentialViewSetTests. """

    list_path = reverse("api:v1:coursecredential-list")

    def setUp(self):
        super(CourseCredentialViewSetTests, self).setUp()

        self.course_certificate = factories.CourseCertificateFactory()
        self.course_id = self.course_certificate.course_id
        self.user_credential = factories.UserCredentialFactory.create(credential=self.course_certificate)

    def test_list_without_course_id(self):
        """ Verify a list end point of course credentials will work only with
        course_id filter. Otherwise it will return 400.
        """
        self.assert_list_without_id_filter(self.list_path, {
            'error': 'A course_id query string parameter is required for filtering course credentials.'
        })

    def test_list_with_course_id(self):
        """ Verify the list endpoint supports filter data by course_id."""
        course_cert = factories.CourseCertificateFactory(course_id="fake-id")
        factories.UserCredentialFactory.create(credential=course_cert)
        self.assert_list_with_id_filter(data={'course_id': self.course_id})

    def test_list_with_status_filter(self):
        """ Verify the list endpoint supports filtering by status."""
        factories.UserCredentialFactory.create_batch(2, status="revoked", username=self.user_credential.username)
        self.assert_list_with_status_filter(data={'course_id': self.course_id, 'status': UserCredential.AWARDED})

    def test_list_with_certificate_type(self):
        """ Verify the list endpoint supports filtering by certificate_type."""
        course_cert = factories.CourseCertificateFactory(certificate_type="verified")
        factories.UserCredentialFactory.create(credential=course_cert)

        # course_id is mandatory
        response = self.client.get(self.list_path, data={'course_id': self.course_id,
                                                         'certificate_type': self.course_certificate.certificate_type})

        # after filtering it is only one related record
        expected = UserCredentialSerializer(self.user_credential, context={'request': self.request}).data
        self.assertEqual(
            json.loads(response.content),
            {'count': 1, 'next': None, 'previous': None, 'results': [expected]}
        )
