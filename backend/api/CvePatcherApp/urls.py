from django.urls import re_path
from CvePatcherApp import views

from django.conf.urls.static import static  # upload file
from django.conf import settings            # upload file

urlpatterns = [
    re_path(r'^sponsors$', views.sponsorApi),
    re_path(r'^sponsors/([0-9]+)$', views.sponsorApi),

    re_path(r'^users$', views.userApi),
    re_path(r'^users/([0-9]+)$', views.userApi),

    re_path(r'^bounties$', views.bountyApi),
    re_path(r'^bounties/([0-9]+)$', views.bountyApi),

    re_path(r'^userregisteredbounties$', views.userRegisteredBountyApi),
    re_path(r'^userregisteredbounties/([0-9]+)$', views.userRegisteredBountyApi),

    re_path(r'^sponsorpoints$', views.sponsorPointApi),
    re_path(r'^sponsorpoints/([0-9]+)$', views.sponsorPointApi),

    re_path(r'^savefile$', views.SaveFile),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)