""" API v1 URLs. """
from rest_framework.routers import DefaultRouter

from credentials.apps.api.v1 import views


router = DefaultRouter()  # pylint: disable=invalid-name
router.register(r'user_credentials', views.UserCredentialViewSet)

urlpatterns = router.urls
