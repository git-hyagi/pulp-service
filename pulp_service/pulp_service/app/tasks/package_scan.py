import aiohttp
import asyncio
import json
import re
import threading

from asgiref.sync import sync_to_async
from django.conf import settings
from queue import Empty, Queue

from pulpcore.plugin.sync import sync_to_async_iterable
from pulpcore.plugin.util import get_domain
from pulpcore.plugin.models import CreatedResource, RepositoryVersion, PulpTemporaryFile
from pulp_npm.app.models import Package as NPMPackage
from pulp_service.app.constants import (
    OSV_RH_ECOSYSTEM_CPES_LABEL,
    OSV_RH_ECOSYSTEM_LABEL,
    OSV_QUERY_URL,
    PKG_ECOSYSTEM,
    VULNERABILITY_TASK_THREAD_TIMEOUT,
)
from pulp_service.app.models import VulnerabilityReport
from pulp_service.app.tasks.util import except_catch_and_raise

# Create a thread-safe queue to share Content units between threads
#content_queue = Queue()

# CPE prefix from Red Hat packages
cpe_prefix = re.compile(r"^cpe:\/[oa]:redhat")


async def check_content_from_repo_version(repo_version_pk):
    """
    Spawn a thread to retrieve the list of packages in RepoVersion(repo_version_pk) and
    make a request to osv.dev API to check the vulnerabilities.
    """
    tasks = []
    async for contents in _get_content_from_repo_version(repo_version_pk):
        tasks.append(asyncio.create_task(_scan_packages(contents)))
    await asyncio.gather(*tasks)


async def check_npm_package(npm_package):
    """
    Spawn a thread to parse the package-json.lock file and make a request to osv.dev API
    with each dependency found.
    """
    return 
    # create a thread to collect the Contents from package-lock.json file
    #background_thread = threading.Thread(target=_parse_npm_pkg_dependencies, args=(npm_package,))
    #await _start_thread_and_run_scan(background_thread)


async def _start_thread_and_run_scan(background_thread):
    """
    Start the background_thread and make the API requests (scan) to osv.dev with the packages
    from Queue
    """
    background_thread.start()
    await _scan_packages(background_thread)
    background_thread.join()


#async def _scan_packages(background_thread):
async def _scan_packages(osv_data):
    """
    Makes a request to the osv.dev API and store the results in VulnerabilityReport model.
    """
    semaphore = asyncio.Semaphore(settings.VULN_REPORT_TASK_LIMITER)
    async with semaphore:
        async with aiohttp.ClientSession() as session:
            repo_version = osv_data.pop("repo_version", None)
            content = osv_data.pop("content")
            async with session.post(url=OSV_QUERY_URL, json=osv_data) as response:
                try:
                    json_body = await response.json()
                except aiohttp.ContentTypeError:
                    raise RuntimeError("Vuln report task failed to query osv.dev data.")
                vulns = json_body["vulns"] if json_body.get("vulns") else []
                if next_page_token := json_body.get("next_page_token"):
                    osv_data["page_token"] = next_page_token
                    osv_data["repo_version"] = repo_version

                vuln_report, created = await sync_to_async(VulnerabilityReport.objects.update_or_create)(
                    vulns=vulns, pulp_domain=get_domain(), content=content
                )
                await sync_to_async(vuln_report.repo_versions.add)(repo_version)
                if created:
                    await CreatedResource.objects.acreate(content_object=vuln_report)



#@except_catch_and_raise(content_queue)
#def _get_content_from_repo_version(repo_version_pk: str):
async def _get_content_from_repo_version(repo_version_pk: str):
    """
    Populate content_queue Queue with the content_units found in RepositoryVersion
    """
    repo_version = await sync_to_async(RepositoryVersion.objects.get)(pk=repo_version_pk)
    repository = await sync_to_async(lambda: repo_version.repository)()
    content_units = await sync_to_async(list)(repo_version.content.all())
    
    for content_unit in content_units:
        content = await sync_to_async(content_unit.cast)()
        content_name = await sync_to_async(lambda: content.name)()
        content_version = await sync_to_async(lambda: content.version)()
        ecosystems = await sync_to_async(_identify_package_ecosystem)(content, repository)
        for ecosystem in ecosystems:
            osv_data = _build_osv_data(content_name, ecosystem, content_version)
            osv_data["repo_version"] = repo_version
            osv_data["content"] = content
            yield osv_data

#@except_catch_and_raise(content_queue)
#def _parse_npm_pkg_dependencies(package_lock_content):
#    """
#    Parse the package-lock.json file to extract the packages[name][dependencies] and
#    add them to content_queue Queue
#
#    notes:
#    - we are striping the "~" and "^" from versions because osv.dev has no support to version range
#    - the old/legacy packages[dependencies] field is not supported
#    """
#    temp_file = PulpTemporaryFile.objects.get(pk=package_lock_content)
#    package_lock_content = json.loads(temp_file.file.read())
#    temp_file.delete()
#    for pkg in package_lock_content.get("packages", None):
#        if not package_lock_content["packages"][pkg].get("dependencies", None):
#            continue
#        for package_name, package_version in package_lock_content["packages"][pkg][
#            "dependencies"
#        ].items():
#            # we will not handle version range yet, for now, we will consider
#            # only the specific version
#            package_version = package_version.strip("^~")
#            osv_data = _build_osv_data(package_name, PKG_ECOSYSTEM.npm, package_version)
#            content_queue.put(osv_data)
#    content_queue.put(None)  # signal that there is no more content_units


def _build_osv_data(name, ecosystem, version=None, next_page_token=None):
    """
    Helper function to build the osv.dev request data based on content object
    """
    osv_data = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        osv_data["version"] = version
    if next_page_token:
        osv_data["page_token"] = next_page_token
    return osv_data


def _identify_package_ecosystem(content, repository=None):
    """
    Returns an osv.dev ecosystem (string) based on the content_type
    """
    if isinstance(content, NPMPackage):
        return [getattr(PKG_ECOSYSTEM, "npm", None)]
    elif content.TYPE in ["python", "gem"]:
        return [getattr(PKG_ECOSYSTEM, content.TYPE, None)]
    elif repository and repository.pulp_type == "rpm.rpm":
        if content.pulp_type == "rpm.package":
            return _convert_rhel_repo_cpe(repository)
        else:
            # ignore non rpm packages (advisory, packagecategory, packagelangpacks)
            return []
    else:
        raise RuntimeError("Package type not supported!")


def _convert_rhel_repo_cpe(repo):
    """
    Convert the CPE into osv.dev expected format
    """
    ecosystem = []
    for cpe in json.loads(repo.pulp_labels[OSV_RH_ECOSYSTEM_CPES_LABEL]):
        ecosystem.append(cpe_prefix.sub(repo.pulp_labels[OSV_RH_ECOSYSTEM_LABEL], cpe))
    return ecosystem
