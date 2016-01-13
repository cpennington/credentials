"""
Helper methods for credential app.
"""
import datetime
import hashlib
from itertools import groupby
import logging

from django.conf import settings
from django.core.cache import cache
from edx_rest_api_client.client import EdxRestApiClient
import jwt


log = logging.getLogger(__name__)
PROGRAMS_CACHE_KEY = 'programs.api.data'
ORGANIZATIONS_CACHE_KEY = 'organizations.api.data'
USER_CACHE_KEY = 'user.api.data'


def validate_duplicate_attributes(attributes):
    """
    Validate the attributes data

    Arguments:
        attributes (list): List of dicts contains attributes data

    Returns:
        Boolean: Return True only if data has no duplicated namespace and name

    """
    def keyfunc(attribute):  # pylint: disable=missing-docstring
        return attribute['name']

    sorted_data = sorted(attributes, key=keyfunc)
    for __, group in groupby(sorted_data, key=keyfunc):
        if len(list(group)) > 1:
            return False
    return True


def get_programs():
    """ Get active programs from the Programs service on behalf of the
    credentials service user present in the Programs service.

    Returned value is cached to avoid calling programs service each time a
    certificate is viewed.

    Returns:
        list of dict, representing programs returned by the Programs service.
    """
    no_programs = []

    cached = cache.get(PROGRAMS_CACHE_KEY)
    if cached is not None:
        return cached

    programs_api = get_program_api_client()
    if programs_api is None:
        return no_programs

    try:
        response = programs_api.programs.get()
    except Exception:  # pylint: disable=broad-except
        log.exception('Failed to retrieve programs from the Programs API.')
        return no_programs

    results = response.get('results', no_programs)
    cache.set(PROGRAMS_CACHE_KEY, results, settings.PROGRAMS_CACHE_TTL)

    return results


def get_organization(organization_key):
    """ Get the organization from the edx-platform on behalf of the
    credentials service user present in the edx-platform system.
    Returned value is cached to avoid calling LMS each time a certificate is
    viewed.

    Arguments:
        organization_key (str): Unique key of the organization for retrieval

    Returns:
        dict, representing organization data returned by the LMS.
    """
    no_organization = {}
    # ensure that the 'organization_key' contains only ASCII characters
    try:
        organization_key.decode('ascii')
    except UnicodeDecodeError:
        log.exception('Invalid organization key %s.', organization_key)
        return no_organization

    cache_key = ORGANIZATIONS_CACHE_KEY + '.{}'.format(_make_hash(organization_key))
    organization = cache.get(cache_key)

    if organization is not None:
        return organization

    organizations_api = get_organizations_api_client()
    if organizations_api is None:
        return no_organization

    try:
        organization = organizations_api.organization(organization_key).get()
    except Exception:  # pylint: disable=broad-except
        log.exception('Failed to retrieve organization with key %s from the Organization API.', organization_key)
        return no_organization

    cache.set(cache_key, organization, settings.ORGANIZATIONS_CACHE_TTL)

    return organization


def get_user(username):
    """ Get the user data from the edx-platform on behalf of the
    credentials service user present in the edx-platform system.
    Returned value is cached to avoid calling LMS each time a certificate is
    viewed.

    Arguments:
        username (str): Unique identifier of the user for retrieval

    Returns:
        dict, representing user data returned by the LMS.
    """
    no_user = {}
    # ensure that the 'username' contains only ASCII characters
    try:
        username.decode('ascii')
    except UnicodeDecodeError:
        log.exception('Invalid username %s.', username)
        return no_user

    cache_key = USER_CACHE_KEY + '.{}'.format(_make_hash(username))
    user = cache.get(cache_key)

    if user is not None:
        return user

    user_api = get_user_api_client()
    if user_api is None:
        return no_user

    try:
        user = user_api.accounts(username).get()
    except Exception:  # pylint: disable=broad-except
        log.exception('Failed to retrieve user with username %s from the User API.', username)
        return no_user

    cache.set(cache_key, user, settings.USER_CACHE_TTL)

    return user


def get_program_api_client():
    """
    Return api client to communicate with the programs service by using the
    credentials service user in the programs service.
    """
    try:
        programs_api_url = settings.PROGRAMS_API_URL
        service_username = settings.CREDENTIALS_SERVICE_USER
        jwt_audience = settings.PROGRAMS_JWT_AUDIENCE
        jwt_secret_key = settings.PROGRAMS_JWT_SECRET_KEY
    except AttributeError:
        log.exception("Failed to get settings for communication with the Programs API. Please make sure that the "
                      "settings for 'PROGRAMS_API_URL', 'CREDENTIALS_SERVICE_USER', 'PROGRAMS_JWT_AUDIENCE', "
                      "'PROGRAMS_JWT_SECRET_KEY' are provided.")
        return None

    return _get_service_user_api_client(programs_api_url, service_username, jwt_audience, jwt_secret_key)


def get_organizations_api_client():
    """
    Return api client to communicate with the organizations api by using the
    credentials service user in the LMS.
    """
    try:
        organizations_api_url = settings.ORGANIZATIONS_API_URL
        service_username = settings.CREDENTIALS_SERVICE_USER
        jwt_audience = settings.ORGANIZATIONS_AUDIENCE
        jwt_secret_key = settings.ORGANIZATIONS_SECRET_KEY
    except AttributeError:
        log.exception("Failed to get settings for communication with the Organizations API. Please make sure that the "
                      "settings for 'ORGANIZATIONS_API_URL', 'CREDENTIALS_SERVICE_USER', 'ORGANIZATIONS_AUDIENCE', "
                      "'ORGANIZATIONS_SECRET_KEY' are provided.")
        return None

    return _get_service_user_api_client(organizations_api_url, service_username, jwt_audience, jwt_secret_key)


def get_user_api_client():
    """
    Return api client to communicate with the user api by using the credentials
    service user in the LMS.
    """
    try:
        user_api_url = settings.USER_API_URL
        service_username = settings.CREDENTIALS_SERVICE_USER
        jwt_audience = settings.USER_JWT_AUDIENCE
        jwt_secret_key = settings.USER_JWT_SECRET_KEY
    except AttributeError:
        log.exception("Failed to get settings for communication with the User API. Please make sure that the "
                      "settings for 'USER_API_URL', 'CREDENTIALS_SERVICE_USER', 'USER_JWT_AUDIENCE', "
                      "'USER_JWT_SECRET_KEY' are provided.")
        return None

    return _get_service_user_api_client(user_api_url, service_username, jwt_audience, jwt_secret_key, False)


def _get_service_user_api_client(api_url, service_username, jwt_audience, jwt_secret_key, append_slash=True):
    """
    Helper method to get edx rest api client for the provided service user
    which is present on the system from 'api_url'.

    Arguments:
        api_url (str): Absolute url of the api
        service_username (str): Username of the service user
        jwt_audience (str): JWT key for the api auth
        jwt_secret_key (str): JWT secret key for the api auth

    """
    now = datetime.datetime.utcnow()
    expires_in = getattr(settings, 'OAUTH_ID_TOKEN_EXPIRATION', 30)
    payload = {
        'preferred_username': service_username,
        'iss': settings.SOCIAL_AUTH_EDX_OIDC_URL_ROOT,
        'exp': now + datetime.timedelta(seconds=expires_in),
        'iat': now,
        'aud': jwt_audience,
    }

    try:
        jwt_data = jwt.encode(payload, jwt_secret_key)
        api_client = EdxRestApiClient(api_url, jwt=jwt_data, append_slash=append_slash)
    except Exception:  # pylint: disable=broad-except
        log.exception("Failed to initialize the API client with url '%s'.", api_url)
        return

    return api_client


def _make_hash(key):
    """
    Returns the string based on a the hash of the provided key.
    """
    return hashlib.md5(key).hexdigest()
