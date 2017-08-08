
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


import subprocess
import json
import os
from pprint import pprint
import time

test_tmp_file=os.getcwd()+os.sep+"dpctloutputtmp.tmp"


def apply_dpctl(test, config, cmd):
    switch_ip = config["switch_ip"]
    if len(switch_ip) == 0:
        assert(0)

    #apply dpctl command     
    #subprocess.call(os.getcwd()+"/dpctl tcp:"+switch_ip+":6633 "+cmd+" > "+test_tmp_file, shell=True)
    subprocess.call("dpctl tcp:"+switch_ip+":6633 "+cmd+" > "+test_tmp_file, shell=True)
    time.sleep(0.2)
    
def apply_dpctl_get_cmd(test, config, cmd):

    #create the tmp file
    if not os.path.isfile(test_tmp_file):
        open(test_tmp_file, "w").close()
        subprocess.call(["sudo", "chmod", "a+w", test_tmp_file])

    apply_dpctl(test, config, cmd)

    #parse result
    with open(test_tmp_file) as tmp_file:
        try:
            json_result=json.loads(tmp_file.read(), encoding='utf-8')
        except ValueError:
            subprocess.call("cat "+ test_tmp_file, shell=True)
            """
            https://docs.python.org/2/library/unittest.html#
            """            
            test.assertTrue(False, "NO json format, dpctl may fail")
    
    return json_result            
    
def apply_dpctl_mod(test, config, cmd):    
    apply_dpctl(test, config, cmd)
    
    