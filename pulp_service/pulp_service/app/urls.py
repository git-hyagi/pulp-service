from django.urls import include, path

from rest_framework.routers import SimpleRouter

from .admin import admin_site
from .viewsets import (
    ContentScan,
    DebugAuthenticationHeadersView,
    InternalServerErrorCheck,
    InternalServerErrorCheckWithException,
    RedirectCheck,
    TaskViewSet,
    TMPNPMScan,
    Vulnerabilities,
)

router = SimpleRouter(trailing_slash=False)
router.register(r"^api/pulp/tmp-npm-scan/", TMPNPMScan, basename="tpm-npm-scan")

urlpatterns = [
    path("api/pulp-admin/", admin_site.urls),
    path("api/pulp/redirect-check/", RedirectCheck.as_view()),
    path("api/pulp/internal-server-error-check/", InternalServerErrorCheck.as_view()),
    path("api/pulp/raise-exception-check/", InternalServerErrorCheckWithException.as_view()),
    path("api/pulp/debug_auth_header/", DebugAuthenticationHeadersView.as_view()),
    path("api/pulp/admin/tasks/", TaskViewSet.as_view({"get": "list"})),
    path("api/pulp/scan/", ContentScan.as_view()),
    path("api/pulp/vulnerabilities/", Vulnerabilities.as_view()),
    path("", include(router.urls)),
]
