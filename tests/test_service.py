import errno
import json
import os
from pathlib import Path

import pytest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file

import pe.pe

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SELF_LOCATION = os.environ.get("FULL_SELF_LOCATION", ROOT_DIR)
SAMPLES_LOCATION = os.environ.get("FULL_SAMPLES_LOCATION", None)


def find_sample(locations, sample):
    # Assume samples are carted
    sample = f"{sample}.cart"

    for location in locations:
        p = [path for path in Path(location).rglob(sample)]
        if len(p) == 1:
            return p[0]

    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), sample)


def list_results(location, strip_extension=".json"):
    result_jsons = os.listdir(os.path.join(location, "tests", "results"))
    return [result[: -len(strip_extension)] for result in result_jsons]


@pytest.fixture()
def sample(request):
    sample_path = find_sample(request.cls.locations, request.param)
    unpack_file(sample_path, os.path.join("/tmp", request.param))
    yield request.param
    os.remove(os.path.join("/tmp", request.param))


def create_service_task(sample):
    return ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {},
            "fileinfo": {
                "magic": "Not Important",
                "md5": "a" * 32,
                "mime": "Not Important",
                "sha1": "a" * 40,
                "sha256": sample,
                "size": 1,
                "type": "Not Important",
            },
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


def drop_ultimate_folder(path):
    path = Path(path)
    return str(path.parents[1].joinpath(path.name))


def generalize_result(result):
    if "response" in result:
        # Ignore the service_started and service_completed timestamps
        if "milestones" in result["response"]:
            if "service_started" in result["response"]["milestones"]:
                result["response"]["milestones"]["service_started"] = None
            if "service_completed" in result["response"]["milestones"]:
                result["response"]["milestones"]["service_completed"] = None

        # Ignore the service_version and service_name
        if "service_version" in result["response"]:
            result["response"]["service_version"] = None
        if "service_name" in result["response"]:
            result["response"]["service_name"] = None

        # Ignore the extracted and supplementary randomized last folder
        if "extracted" in result["response"]:
            for extracted in result["response"]["extracted"]:
                if "path" in extracted:
                    extracted["path"] = drop_ultimate_folder(extracted["path"])
        if "supplementary" in result["response"]:
            for supplementary in result["response"]["supplementary"]:
                if "path" in supplementary:
                    supplementary["path"] = drop_ultimate_folder(supplementary["path"])


class TestService:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]
        # Ensure all files in results ends with .json
        result_jsons = os.listdir(os.path.join(SELF_LOCATION, "tests", "results"))
        assert all([result.endswith(".json") for result in result_jsons])

    @staticmethod
    @pytest.mark.parametrize("sample", list_results(SELF_LOCATION), indirect=True)
    def test_service(sample):
        cls = pe.pe.PE()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(SELF_LOCATION, "tests", "results", f"{task.file_name}.json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert values of the class instance are expected
        assert cls.file_res == service_request.result

        generalize_result(test_result)
        generalize_result(correct_result)
        assert test_result == correct_result
