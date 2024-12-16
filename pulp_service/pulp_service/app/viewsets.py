import json
import logging

from base64 import b64decode
from binascii import Error as Base64DecodeError

from django.conf import settings
from django.db.models import Sum
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import APIView

from pulpcore.app.models import Artifact
from pulpcore.app.viewsets import RolesMixin
from pulpcore.app.viewsets import ContentGuardViewSet, RolesMixin

from pulp_service.app.models import FeatureContentGuard
from pulp_service.app.serializers import FeatureContentGuardSerializer
from pulp_service.app.authentication import (
    RHServiceAccountCertAuthentication,
    RHEntitlementCertAuthentication,
)


_logger = logging.getLogger(__name__)


class RedirectCheck(APIView):
    """
    Handles requests to the /api/redirect-check/ endpoint.
    """

    # allow anyone to access the endpoint
    authentication_classes = []
    permission_classes = []

    def head(self, request=None, path=None, pk=None):
        """
        Responds to HEAD requests for the redirect-check endpoint.
        """
        return redirect("/api/")


# returning 500 error in a "graceful" way
class InternalServerErrorCheck(APIView):
    """
    Handles requests to the /api/internal-server-error-check/ endpoint.
    """

    # allow anyone to access the endpoint
    authentication_classes = []
    permission_classes = []

    def head(self, request=None, path=None, pk=None):
        """
        Responds to HEAD requests for the internal-server-error-check endpoint.
        """
        return Response(data=None, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# raising an exception (helpful to verify middleware's behavior, for example, otel)
class InternalServerErrorCheckWithException(APIView):
    """
    Handles requests to the /api/raise-exception-check/ endpoint.
    """

    # allow anyone to access the endpoint
    authentication_classes = []
    permission_classes = []

    def head(self, request=None, path=None, pk=None):
        """
        Responds to HEAD requests for the raise-exception-check endpoint.
        """
        # the drf APIException returns a HTTP_500_INTERNAL_SERVER_ERROR
        raise APIException()


class FeatureContentGuardViewSet(ContentGuardViewSet, RolesMixin):
    """
    Content guard to protect the content guarded by Subscription Features.
    """

    endpoint_name = "feature"
    queryset = FeatureContentGuard.objects.all()
    serializer_class = FeatureContentGuardSerializer


class DebugAuthenticationHeadersView(APIView):
    """
    Returns the content of the authentication headers.
    """

    authentication_classes = [RHServiceAccountCertAuthentication]
    permission_classes = []

    def get(self, request=None, path=None, pk=None):
        if not settings.AUTHENTICATION_HEADER_DEBUG:
            raise PermissionError("Access denied.")
        try:
            header_content = request.headers["x-rh-identity"]
        except KeyError:
            _logger.error(
                "Access not allowed. Header {header_name} not found.".format(
                    header_name=settings.AUTHENTICATION_JSON_HEADER
                )
            )
            raise PermissionError("Access denied.")

        try:
            header_decoded_content = b64decode(header_content)
        except Base64DecodeError:
            _logger.error("Access not allowed - Header content is not Base64 encoded.")
            raise PermissionError("Access denied.")

        json_header_value = json.loads(header_decoded_content)
        return Response(data=json_header_value)


class DomainStorageUsage(APIView):
    """
    Returns the domain(s) storage usage
    """

    authentication_classes = []
    permission_classes = []

    @extend_schema(
        summary="Retrieve the domain(s) storage usage in bytes",
        operation_id="domain_storage_usage_read",
        responses={200: None},
    )
    def head(self, request, domain=None):
        """
        Responds to HEAD requests about domain(s) storage usage
        """
        return self._storage_usage(domain)

    def _storage_usage(self, domain_name=None):
        """
        Returns an HttpResponse with X-Pulp-Domain-Name and X-Pulp-Domain-Storage-Usage headers
        """
        space_usage_per_domain = self._domain_storage_usage(domain_name)
        if not space_usage_per_domain:
            return Response(None, status=404)

        response = Response()
        count = 1
        for domain in space_usage_per_domain:
            domain_name = domain["pulp_domain__name"]
            storage_used = domain["total_size"]
            _logger.info("Storage usage by %s domain: %d", domain_name, storage_used)
            count_suffix = f"-{count}" if len(space_usage_per_domain) > 1 else ""
            response[f"X-Pulp-Domain-Name{count_suffix}"] = domain_name
            response[f"X-Pulp-Domain-Storage-Usage{count_suffix}"] = storage_used
            count += 1
        return response

    def _domain_storage_usage(self, domain_name=None):
        """
        Returns the sum of the size of all artifacts from a specific domain if domain_name is
        provided, else, for each available domain, returns the sum of the size of all artifacts.
        """
        artifacts = Artifact.objects.values("pulp_domain__name")
        if domain_name:
            artifacts = artifacts.filter(pulp_domain__name=domain_name)
        return artifacts.annotate(total_size=Sum("size"))
