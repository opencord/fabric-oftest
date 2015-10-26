import subprocess
import json
import os
from pprint import pprint

test_tmp_file=os.getcwd()+os.sep+"dpctloutputtmp.tmp"


def apply_dpctl_cmd(test, config, cmd):
    switch_ip = config["switch_ip"]
    if len(switch_ip) == 0:
        assert(0)
        
    #create the tmp file
    try:
        subprocess.check_call(["ls", test_tmp_file])            
    except subprocess.CalledProcessError:
        open(test_tmp_file, "w").close()
        subprocess.call(["sudo", "chmod", "a+w", test_tmp_file])

    #apply dpctl command     
    subprocess.call("dpctl tcp:"+switch_ip+":6633 "+cmd+" > "+test_tmp_file, shell=True)

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