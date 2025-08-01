from django.urls import path,include

from .admin import admin_site
from .viewsets import (
    CreateDomainView,
    DebugAuthenticationHeadersView,
    InternalServerErrorCheck,
    InternalServerErrorCheckWithException,
    RedirectCheck,
    TaskViewSet,
    TaskIngestionDispatcherView,
    TestVulnerabilityReport,
    TestVulnerabilityReportRepo,
)

from rest_framework import routers

router = routers.SimpleRouter()
head_route = routers.Route(
    url=r"^{prefix}/{lookup}{trailing_slash}$",
    mapping={"head": "head"},
    name="{basename}-detail",
    detail=True,
    initkwargs={"suffix": "Instance"},
)

router.routes.append(head_route)
urlpatterns = [
    path("", include(router.urls)),
    path("api/pulp-admin/", admin_site.urls),
    path("api/pulp/redirect-check/", RedirectCheck.as_view()),
    path("api/pulp/internal-server-error-check/", InternalServerErrorCheck.as_view()),
    path("api/pulp/raise-exception-check/", InternalServerErrorCheckWithException.as_view()),
    path("api/pulp/debug_auth_header/", DebugAuthenticationHeadersView.as_view()),
    path("api/pulp/admin/tasks/", TaskViewSet.as_view({"get": "list"})),
    path("api/pulp/test/tasks/", TaskIngestionDispatcherView.as_view()),
    path("api/pulp/create-domain/", CreateDomainView.as_view()),
    path("api/pulp/test_vuln_report/", TestVulnerabilityReport.as_view({"get": "list"})),
    path("api/pulp/test_repo/", TestVulnerabilityReportRepo.as_view({"get": "list"})),
]
