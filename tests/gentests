#!/bin/env python
import os

from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

cwd = os.getcwd()
# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(cwd, "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(cwd, "tests", "results")

# Find which module we're working on
for line in open('Dockerfile', 'r').readlines():
    if line.startswith("ENV SERVICE_PATH"):
        module = line[17:].strip()
        break

# Initialize test helper
service_class = load_module_by_path(module, cwd)
th = TestHelper(service_class, RESULTS_FOLDER)

th.regenerate_results(save_files=["features.json"])
