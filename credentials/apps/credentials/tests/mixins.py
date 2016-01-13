"""
Mixins for use during testing.
"""
import json

import httpretty

from django.conf import settings


class ProgramsDataMixin(object):
    """ Mixin mocking Programs API URLs and providing fake data for testing."""
    PROGRAM_NAMES = [
        'Test Program A',
        'Test Program B',
    ]

    COURSE_KEYS = [
        'organization-a/course-a/fall',
        'organization-a/course-a/winter',
        'organization-a/course-b/fall',
        'organization-a/course-b/winter',
        'organization-b/course-c/fall',
        'organization-b/course-c/winter',
        'organization-b/course-d/fall',
        'organization-b/course-d/winter',
    ]

    PROGRAMS_API_RESPONSE = {
        'results': [
            {
                'id': 1,
                'name': PROGRAM_NAMES[0],
                'subtitle': 'A program used for testing purposes',
                'category': 'xseries',
                'status': 'unpublished',
                'marketing_slug': '',
                'organizations': [
                    {
                        'display_name': 'Test Organization A',
                        'key': 'organization-a'
                    }
                ],
                'course_codes': [
                    {
                        'display_name': 'Test Course A',
                        'key': 'course-a',
                        'organization': {
                            'display_name': 'Test Organization A',
                            'key': 'organization-a'
                        },
                        'run_modes': [
                            {
                                'course_key': COURSE_KEYS[0],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'fall'
                            },
                            {
                                'course_key': COURSE_KEYS[1],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'winter'
                            }
                        ]
                    },
                    {
                        'display_name': 'Test Course B',
                        'key': 'course-b',
                        'organization': {
                            'display_name': 'Test Organization A',
                            'key': 'organization-a'
                        },
                        'run_modes': [
                            {
                                'course_key': COURSE_KEYS[2],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'fall'
                            },
                            {
                                'course_key': COURSE_KEYS[3],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'winter'
                            }
                        ]
                    }
                ],
                'created': '2015-10-26T17:52:32.861000Z',
                'modified': '2015-11-18T22:21:30.826365Z'
            },
            {
                'id': 2,
                'name': PROGRAM_NAMES[1],
                'subtitle': 'Another program used for testing purposes',
                'category': 'xseries',
                'status': 'unpublished',
                'marketing_slug': '',
                'organizations': [
                    {
                        'display_name': 'Test Organization B',
                        'key': 'organization-b'
                    }
                ],
                'course_codes': [
                    {
                        'display_name': 'Test Course C',
                        'key': 'course-c',
                        'organization': {
                            'display_name': 'Test Organization B',
                            'key': 'organization-b'
                        },
                        'run_modes': [
                            {
                                'course_key': COURSE_KEYS[4],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'fall'
                            },
                            {
                                'course_key': COURSE_KEYS[5],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'winter'
                            }
                        ]
                    },
                    {
                        'display_name': 'Test Course D',
                        'key': 'course-d',
                        'organization': {
                            'display_name': 'Test Organization B',
                            'key': 'organization-b'
                        },
                        'run_modes': [
                            {
                                'course_key': COURSE_KEYS[6],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'fall'
                            },
                            {
                                'course_key': COURSE_KEYS[7],
                                'mode_slug': 'verified',
                                'sku': '',
                                'start_date': '2015-11-05T07:39:02.791741Z',
                                'run_key': 'winter'
                            }
                        ]
                    }
                ],
                'created': '2015-10-26T19:59:03.064000Z',
                'modified': '2015-10-26T19:59:18.536000Z'
            }
        ]
    }

    def mock_programs_api(self, data=None, status_code=200):
        """ Utility for mocking out Programs API URLs."""
        self.assertTrue(httpretty.is_enabled(), msg='httpretty must be enabled to mock Programs API calls.')

        programs_api_url = settings.PROGRAMS_API_URL
        url = programs_api_url.strip('/') + '/programs/'

        if data is None:
            data = self.PROGRAMS_API_RESPONSE

        body = json.dumps(data)

        httpretty.reset()
        httpretty.register_uri(httpretty.GET, url, body=body, content_type='application/json', status=status_code)


class OrganizationsDataMixin(object):
    """ Mixin mocking Organizations API URLs and providing fake data for testing."""
    ORGANIZATIONS_API_RESPONSE = {
        'name': 'Test Organization',
        'short_name': 'test-org',
        'description': 'Oraganization for testing.',
        'logo': 'http://testserver/media/organization_logos/test_org_logo.png',
    }

    def mock_organizations_api(self, organization_key, status_code=200):
        """ Utility for mocking out Organizations API URLs."""
        self.assertTrue(httpretty.is_enabled(), msg='httpretty must be enabled to mock Organizations API calls.')

        organizations_api_url = settings.ORGANIZATIONS_API_URL
        url = organizations_api_url.strip('/') + '/organization/{}/'.format(organization_key)

        # only return data for test org
        if organization_key == 'test-org':
            data = self.ORGANIZATIONS_API_RESPONSE
        else:
            data = None
            status_code = 404

        body = json.dumps(data)

        httpretty.reset()
        httpretty.register_uri(httpretty.GET, url, body=body, content_type='application/json', status=status_code)


class UserDataMixin(object):
    """ Mixin mocking User API URLs and providing fake data for testing."""
    USER_API_RESPONSE = {
        "username": "test-user",
        "bio": "A test user.",
        "requires_parental_consent": False,
        "name": "Test User",
        "country": None,
        "is_active": True,
        "profile_image": {
            "image_url_full": "http://localhost:8000/static/images/profiles/default_500.png",
            "image_url_large": "http://localhost:8000/static/images/profiles/default_120.png",
            "image_url_medium": "http://localhost:8000/static/images/profiles/default_50.png",
            "image_url_small": "http://localhost:8000/static/images/profiles/default_30.png",
            "has_image": False
        },
        "year_of_birth": None,
        "level_of_education": None,
        "goals": None,
        "language_proficiencies": [],
        "gender": None,
        "account_privacy": "private",
        "mailing_address": None,
        "email": "test@example.org",
        "date_joined": "2015-11-17T03:16:01Z"
    }

    def mock_user_api(self, username, status_code=200):
        """ Utility for mocking out User API URLs."""
        self.assertTrue(httpretty.is_enabled(), msg='httpretty must be enabled to mock User API calls.')

        user_api_url = settings.USER_API_URL
        url = user_api_url.strip('/') + '/accounts/{}'.format(username)

        # only return data for test user
        if username == 'test-user':
            data = self.USER_API_RESPONSE
        else:
            data = None
            status_code = 404

        body = json.dumps(data)

        httpretty.reset()
        httpretty.register_uri(httpretty.GET, url, body=body, content_type='application/json', status=status_code)
