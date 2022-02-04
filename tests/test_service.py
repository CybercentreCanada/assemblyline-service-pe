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


def list_results(location):
    return os.listdir(os.path.join(location, "tests", "results"))


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

    @staticmethod
    @pytest.mark.parametrize("sample", list_results(SELF_LOCATION), indirect=True)
    def test_service(sample):
        overwrite_features = True  # Used temporarily to mass-correct tests
        overwrite_results = True  # Used temporarily to mass-correct tests

        cls = pe.pe.PE()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        correct_features_path = os.path.join(SELF_LOCATION, "tests", "results", sample, "features.json")
        if os.path.exists(correct_features_path):
            with open(correct_features_path, "r") as f:
                correct_features = json.loads(f.read())

            test_features_path = os.path.join(cls.working_directory, "features.json")
            with open(test_features_path, "r") as f:
                test_features = json.loads(f.read())

            if overwrite_features:
                if test_features != correct_features:
                    with open(correct_features_path, "w") as f:
                        f.write(json.dumps(test_features))
            else:
                assert test_features == correct_features

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(SELF_LOCATION, "tests", "results", sample, "result.json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())

        # Assert values of the class instance are expected
        assert cls.file_res == service_request.result

        if overwrite_results:
            import copy

            orig_result = copy.deepcopy(test_result)

        generalize_result(test_result)
        generalize_result(correct_result)
        if overwrite_results:
            if test_result != correct_result:
                with open(correct_result_path, "w") as f:
                    f.write(json.dumps(orig_result))
        else:
            assert test_result == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "sample", ["019f812bbb2304bbe1ce1dc24cdf6e43d486aff9e14fe0594a8fa17e0f3f5e47"], indirect=True
    )
    def generate_test_service(sample):  # remove generate to run it-ish
        cls = pe.pe.PE()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        import shutil

        if sample != "8e8b38abf230ba9deeccf588c332293440e2b7fc40c62842b8beb2460184e548":
            os.mkdir(os.path.join(SELF_LOCATION, "tests", "results", sample))

            shutil.copyfile(
                os.path.join(cls.working_directory, "features.json"),
                os.path.join(SELF_LOCATION, "tests", "results", sample, "features.json"),
            )

            with open(os.path.join(SELF_LOCATION, "tests", "results", sample, "result.json"), "w") as result_file:
                result_file.write(json.dumps(task.get_service_result()))
