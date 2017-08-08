
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


'''Docstring to silence pylint; ignores --ignore option for __init__.py'''
import sys
import os
import logging

# Global config dictionary
# Populated by oft.
config = {}

# Global DataPlane instance used by all tests.
# Populated by oft.
dataplane_instance = None

def open_logfile(name):
    """
    (Re)open logfile

    When using a log directory a new logfile is created for each test. The same
    code is used to implement a single logfile in the absence of --log-dir.
    """

    _format = "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s"
    _datefmt = "%H:%M:%S"

    if config["log_dir"] != None:
        filename = os.path.join(config["log_dir"], name) + ".log"
    else:
        filename = config["log_file"]

    logger = logging.getLogger()

    # Remove any existing handlers
    for handler in logger.handlers:
        logger.removeHandler(handler)
        handler.close()

    # Add a new handler
    handler = logging.FileHandler(filename, mode='a')
    handler.setFormatter(logging.Formatter(_format, _datefmt))
    logger.addHandler(handler)
