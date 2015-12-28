""" Accreditor class identifies relative issuer."""
from __future__ import unicode_literals
import logging

from credentials.apps.api import exceptions
from credentials.apps.credentials.issuers import ProgramCertificateIssuer


logger = logging.getLogger(__name__)


class Accreditor(object):
    """ Accreditor class identifies credential type and calls corresponding issuer
    class for generating credential.
    """
    def __init__(self, issuers=None):
        if not issuers:
            issuers = [ProgramCertificateIssuer()]

        self.issuers = issuers
        self._create_credential_type_issuer_map()

    def _create_credential_type_issuer_map(self):
        """Creates a map from credential type slug to a list of credential issuers."""
        self.credential_type_issuer_map = {}
        for issuer in self.issuers:
            credential_type_slug = issuer.issued_credential_type.credential_type_slug
            registered_issuer = self.credential_type_issuer_map.get(credential_type_slug)
            if not registered_issuer:
                self.credential_type_issuer_map[credential_type_slug] = issuer
            else:
                logger.warning(
                    "The issuer [%s] is already registered to issue credentials of type [%s]. [%s] will NOT be used.",
                    registered_issuer, credential_type_slug, issuer)

    def issue_credential(self, credential_type, username, **kwargs):
        """Issues a credential.

        Arguments:
            credential_type (string): Type of credential to be issued.
            username (string): Username of the recipient.
            **kwargs (dict): Arbitrary keyword arguments passed to the issuer class.

        Returns:
            UserCredential

        Raises:
            UnsupportedCredentialTypeError: If the specified credential type is not supported (cannot be issued).
        """
        try:
            credential_issuer = self.credential_type_issuer_map[credential_type]
        except KeyError:
            raise exceptions.UnsupportedCredentialTypeError(
                "Unable to issue credential. No issuer is registered for credential type [{}]".format(credential_type)
            )

        return credential_issuer.issue_credential(username, **kwargs)
