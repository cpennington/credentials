"""credentials URL Configuration
The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""

import os

from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.views import logout
from django.core.urlresolvers import reverse_lazy
from django.views.generic import RedirectView

from credentials.apps.core import views as core_views

admin.autodiscover()

# pylint: disable=invalid-name
# Always login via edX OpenID Connect
login = RedirectView.as_view(url=reverse_lazy('social:begin', args=['edx-oidc']), permanent=False, query_string=True)

AUTH_URLS = [
    url(r'^login/$', login, name='login'),
    url(r'^logout/$', logout, name='logout'),
]

urlpatterns = [
    url(r'^accounts/', include(AUTH_URLS)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include('credentials.apps.api.urls', namespace='api')),
    url(r'^api-auth/', include(AUTH_URLS, namespace='rest_framework')),
    url(r'^auto_auth/$', core_views.AutoAuth.as_view(), name='auto_auth'),
    url(r'^credentials/', include('credentials.apps.credentials.urls', namespace='credentials')),
    url(r'^health/$', core_views.health, name='health'),
    url(r'^jsi18n/$', 'django.views.i18n.javascript_catalog', ''),
    url('', include('social.apps.django_app.urls', namespace='social')),
]

# Add media and extra urls
if settings.DEBUG:  # pragma: no cover
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG and os.environ.get('ENABLE_DJANGO_TOOLBAR', False):  # pragma: no cover
    import debug_toolbar  # pylint: disable=import-error, wrong-import-position, wrong-import-order
    urlpatterns.append(url(r'^__debug__/', include(debug_toolbar.urls)))
