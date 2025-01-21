import argparse
import json
import os
import requests
import subprocess
import sys

from collections import defaultdict
from datetime import datetime, timedelta
from types import SimpleNamespace


DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TASKS_ENDPOINT = "/api/pulp/admin/tasks/?fields=pulp_created&fields=started_at&fields=finished_at&"

QUERY_TYPES = SimpleNamespace(
    RUNNING="running",
    WAITING_UNBLOCKED="waiting_unblocked",
    WAITING_BLOCKED="waiting_blocked",
)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-b",
    "--base_address",
    help="Pulp hostname address. For example: http://pulp-service:5001",
)
parser.add_argument(
    "-u",
    "--username",
    help="Pulp user to run the API requests. [DEFAULT: admin]",
    default="admin",
)
parser.add_argument("-p", "--password", help="Password for Pulp user.")
parser.add_argument(
    "-c", "--certificate", help="Certificate to authenticate to Pulp API."
)
parser.add_argument(
    "-k", "--key", help="Private key for the certificate authentication."
)
parser.add_argument(
    "--period",
    help="Period, in hours, to check the tasks. For example, for the last 24 hours: --period=24 [DEFAULT: 2]",
    type=int,
    default=2,
)
parser.add_argument(
    "--bucket_size",
    help="Bucket size, in seconds. For example, for a 30 seconds bucket: --bucket-size=30 [DEFAULT: 600]",
    type=int,
    default=600,
)
parser.add_argument(
    "-o",
    "--output",
    help="Output file with the metrics. [DEFAULT: /tmp/tasks-cli/pulp_tasks.out]",
    type=str,
    default="/tmp/tasks-cli/pulp_tasks.out",
)
parser.add_argument(
    "-g",
    "--graph_file",
    help="Gnuplot output file. [DEFAULT: /tmp/tasks-cli/graph_tasks.ps]",
    type=str,
    default="/tmp/tasks-cli/graph_tasks.ps",
)

args = parser.parse_args()

base_addr = args.base_address
username = args.username
password = args.password
pulp_certificate = args.certificate
pulp_cert_key = args.key
period_in_hours = args.period
bucket_size_in_seconds = args.bucket_size
output_file = args.output
graph_file = args.graph_file


# running task, 3 situations:
# - started and didn't finish yet (finished_at=null)
# - started and finished in between the current bucket interval
# - started and not finished in between the current bucket interval

# - started and didn't finish yet (finished_at=null)
def running_task(query_date_time, data):
    url = base_addr + TASKS_ENDPOINT + "state=running&started_at__gte="+query_date_time.strftime(DATETIME_FORMAT)
    response = requests.get(url,auth=(username,password))

    if response.status_code // 100 != 2:
        print("ERROR:", response.status_code, response.text)
        sys.exit(1)

    response_json = json.loads(response.text)
    if response_json['count'] > 0:
        data[query_date_time.strftime(DATETIME_FORMAT)]["3-running"] = response_json['count']


def run():

    datetime_now = datetime.now() + timedelta(hours=3)
    query_date_time = datetime_now - timedelta(hours=period_in_hours)
    start_date = query_date_time.strftime(DATETIME_FORMAT)
    #data = initialize_response_structure(
    #    period_in_hours, bucket_size_in_seconds, query_date_time
    #)
    data = defaultdict(lambda: {})

    total_seconds = timedelta(hours=period_in_hours).total_seconds()
    number_of_intervals = int(total_seconds // bucket_size_in_seconds)

    start_interval = query_date_time
    # - started and finished in between the current bucket interval
    while start_interval <= datetime_now:
        end_interval = start_interval + timedelta(seconds=bucket_size_in_seconds)
        #url = base_addr + TASKS_ENDPOINT + "started_at__lte=" + current_interval.strftime(DATETIME_FORMAT) + "&finished_at__gte="+current_interval.strftime(DATETIME_FORMAT)
        url = base_addr + TASKS_ENDPOINT + "started_at__gte=" + start_interval.strftime(DATETIME_FORMAT) + "&finished_at__lte="+end_interval.strftime(DATETIME_FORMAT)
        response = requests.get(url,auth=(username,password))

        if response.status_code // 100 != 2:
            print("ERROR:", response.status_code, response.text)
            sys.exit(1)

        response_json = json.loads(response.text)
        if response_json['count'] > 0:
            data[start_interval.strftime(DATETIME_FORMAT)]["1-running"] = response_json['count']
        
        running_task(start_interval,data)
        
        start_interval = end_interval
    
    # - started and not finished in between the current bucket interval
    start_interval = query_date_time
    while start_interval <= datetime_now:
        end_interval = start_interval + timedelta(seconds=bucket_size_in_seconds)
        #url = base_addr + TASKS_ENDPOINT + "started_at__gte=" + start_interval.strftime(DATETIME_FORMAT) + "&finished_at__lte="+datetime_now.strftime(DATETIME_FORMAT)
        url = base_addr + TASKS_ENDPOINT + "started_at__lte=" + start_interval.strftime(DATETIME_FORMAT) + "&finished_at__lte="+datetime_now.strftime(DATETIME_FORMAT)
        response = requests.get(url,auth=(username,password))

        if response.status_code // 100 != 2:
            print("ERROR:", response.status_code, response.text)
            sys.exit(1)

        response_json = json.loads(response.text)
        if response_json['count'] > 0:
            data[start_interval.strftime(DATETIME_FORMAT)]["2-running"] = response_json['count']
        start_interval = end_interval

    """
    # - started and didn't finish yet (finished_at=null)
    url = base_addr + TASKS_ENDPOINT + "state=running&started_at__gte="+query_date_time.strftime(DATETIME_FORMAT)
    response = requests.get(url,auth=(username,password))

    if response.status_code // 100 != 2:
        print("ERROR:", response.status_code, response.text)
        sys.exit(1)

    response_json = json.loads(response.text)
    if response_json['count'] > 0:
        data[query_date_time.strftime(DATETIME_FORMAT)]["3-running"] = response_json['count']
    """

    print(json.dumps(data, indent=2))


def write_to_file(data):
    try:
        with open(output_file, "w") as f:
            for key in data:
                print(
                    key,
                    data[key][QUERY_TYPES.RUNNING],
                    data[key][QUERY_TYPES.WAITING_BLOCKED],
                    data[key][QUERY_TYPES.WAITING_UNBLOCKED],
                )
                f.write(
                    key
                    + " "
                    + str(data[key][QUERY_TYPES.RUNNING])
                    + " "
                    + str(data[key][QUERY_TYPES.WAITING_BLOCKED])
                    + " "
                    + str(data[key][QUERY_TYPES.WAITING_UNBLOCKED])
                    + "\n"
                )
    except FileNotFoundError:
        dirname = os.path.dirname(os.path.abspath(output_file))
        print(dirname, "not found!")
        print(
            'Make sure',
            dirname,
            'exists or set a different path for the output (tasks-cli -o/--output <file>)',
        )
        sys.exit(2)


def get_tasks(start_date, query_type=None):
    url = base_addr + TASKS_ENDPOINT + "started_at__gte=" + start_date
    if query_type == QUERY_TYPES.RUNNING:
        url = running_tasks_url(start_date)
    elif query_type == QUERY_TYPES.WAITING_UNBLOCKED:
        url = tasks_in_waiting_state_and_unblocked_url(False)
    elif query_type == QUERY_TYPES.WAITING_BLOCKED:
        url = tasks_in_waiting_state_and_unblocked_url(True)

    if pulp_certificate:
        response = requests.get(url, cert=(pulp_certificate, pulp_cert_key))
    else:
        response = requests.get(url, auth=(username, password))

    if response.status_code // 100 != 2:
        print("ERROR:", response.status_code, response.text)
        sys.exit(1)

    response_json = json.loads(response.text)

    tasks_found_datetime = []
    if response_json.get("results"):
        for result in response_json["results"]:
            tasks_found_datetime.append(result["pulp_created"])

    return tasks_found_datetime


def initialize_response_structure(period, bucket_size, query_date_time):
    data = {}
    total_seconds = timedelta(hours=period).total_seconds()
    number_of_intervals = int(total_seconds // bucket_size)

    # Create a list of bucket start times
    bucket_starts = [
        query_date_time + timedelta(seconds=i * bucket_size)
        for i in range(number_of_intervals)
    ]

    # Initialize buckets
    for start_time in bucket_starts:
        data[start_time.strftime(DATETIME_FORMAT)] = {}
        for task_state in QUERY_TYPES.__dict__.values():
            data[start_time.strftime(DATETIME_FORMAT)][task_state] = 0

    return data


def make_buckets(
    tasks_found_datetime, bucket_size, query_date_time, period, query_type, data
):
    if tasks_found_datetime == [None]:
        return data

    total_seconds = timedelta(hours=period).total_seconds()
    number_of_intervals = int(total_seconds // bucket_size)

    # Count tasks in each bucket
    for task_datetime_str in tasks_found_datetime:
        task_datetime = datetime.strptime(task_datetime_str, DATETIME_FORMAT)

        # Find the appropriate bucket for the task
        for i in range(number_of_intervals):
            start_time = query_date_time + timedelta(seconds=i * bucket_size)
            end_time = start_time + timedelta(seconds=bucket_size)

            if start_time < task_datetime < end_time:
                data[start_time.strftime(DATETIME_FORMAT)][query_type] += 1
                break  # Task is counted, no need to check further

    return data


def running_tasks_url(period):
    return (
        base_addr + TASKS_ENDPOINT + "started_at__gte=" + period + "&finished_at__lte="+period
    )


def tasks_in_waiting_state_and_unblocked_url(unblocked_null):
    return (
        base_addr
        + TASKS_ENDPOINT
        + "&state=waiting&unblocked_at__isnull="
        + str(unblocked_null)
    )


run()
