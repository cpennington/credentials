"""
Tests for Issuer class.
"""
import copy

import ddt
import httpretty
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from mock import patch
from testfixtures import LogCapture

from credentials.apps.credentials.tests.mixins import ProgramsDataMixin
from credentials.apps.credentials.utils import get_programs, validate_duplicate_attributes


LOGGER_NAME = 'credentials.apps.credentials.utils'
User = get_user_model()


@ddt.ddt
class ValidateDuplicateAttributesTests(TestCase):
    """ Tests for Validate the attributes method """

    def test_with_non_duplicate_attributes(self):
        """ Verify that the method will return True if no duplicated attributes found."""
        attributes = [
            {"name": "whitelist_reason", "value": "Reason for whitelisting."},
            {"name": "grade", "value": "0.85"}
        ]
        self.assertTrue(validate_duplicate_attributes(attributes))

    def test_with_duplicate_attributes(self):
        """ Verify that the method will return False if duplicated attributes found."""

        attributes = [
            {"name": "whitelist_reason", "value": "Reason for whitelisting."},
            {"name": "whitelist_reason", "value": "Reason for whitelisting."},
        ]

        self.assertFalse(validate_duplicate_attributes(attributes))


@ddt.ddt
class TestProgramRetrieval(ProgramsDataMixin, TestCase):
    """
    Tests covering the retrieval of programs from the Programs service.
    """
    def setUp(self):
        super(TestProgramRetrieval, self).setUp()
        cache.clear()

    @httpretty.activate
    def test_get_programs(self):
        """
        Verify that the programs data can be retrieved.
        """
        self.mock_programs_api()

        actual_programs_api_response = get_programs()
        self.assertEqual(
            actual_programs_api_response,
            self.PROGRAMS_API_RESPONSE['results']
        )

        # verify the API was actually hit (not the cache)
        self.assertEqual(len(httpretty.httpretty.latest_requests), 1)

    @httpretty.activate
    @patch('django.conf.settings.PROGRAMS_CACHE_TTL', 1)
    def test_get_programs_caching(self):
        """ Verify that when the value is set, the cache is used for getting
        programs.
        """
        self.mock_programs_api()

        # hit the Programs API twice
        for _ in range(2):
            get_programs()

        # verify that only one request has been made
        self.assertEqual(len(httpretty.httpretty.latest_requests), 1)

    @patch('edx_rest_api_client.client.EdxRestApiClient.__init__')
    def test_get_programs_client_initialization_failure(self, mock_init):
        """
        Verify the behavior when API client fails to initialize.
        """
        mock_init.side_effect = Exception
        actual_programs_api_response = get_programs()
        self.assertEqual(actual_programs_api_response, [])
        self.assertTrue(mock_init.called)

    @httpretty.activate
    @ddt.data(
        'PROGRAMS_API_URL',
        'CREDENTIALS_SERVICE_USER',
        'PROGRAMS_JWT_AUDIENCE',
        'PROGRAMS_JWT_SECRET_KEY',
    )
    def test_get_programs_client_settings_failure(self, setting_attribute):
        """
        Verify the behavior when API client fails to initialize due to
        missing settings.
        """
        self.mock_programs_api(data={'results': []})
        patched_settings = copy.deepcopy(settings)
        delattr(patched_settings, setting_attribute)
        expected_error_msg = "Failed to get settings for communication with the Programs API. " \
                             "Please make sure that the settings for 'PROGRAMS_API_URL', 'CREDENTIALS_SERVICE_USER'," \
                             " 'PROGRAMS_JWT_AUDIENCE', 'PROGRAMS_JWT_SECRET_KEY' are provided."

        with patch('credentials.apps.credentials.utils.settings', patched_settings):
            with LogCapture(LOGGER_NAME) as log:
                actual_programs_api_response = get_programs()
                self.assertEqual(actual_programs_api_response, [])
                log.check((LOGGER_NAME, 'ERROR', expected_error_msg))

    @httpretty.activate
    def test_get_programs_data_retrieval_failure(self):
        """
        Verify the behavior when data can't be retrieved from Programs.
        """
        self.mock_programs_api(status_code=500)

        actual_programs_api_response = get_programs()
        self.assertEqual(actual_programs_api_response, [])

    @httpretty.activate
    def test_get_programs_with_no_data(self):
        """ Verify the behavior when no programs data is found from the
        Programs service.
        """
        self.mock_programs_api(data={'results': []})

        actual_programs_api_response = get_programs()
        self.assertEqual(actual_programs_api_response, [])
