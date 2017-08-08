
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


#sudo ./oft --verbose --default-timeout=6 -i 1@eth1 -i 2@eth2 -i 3@eth3 --disable-ipv6 --switch-ip=192.168.2.2 --host=192.168.2.4 --of-version=1.3 --port=6633 --test-dir=accton --log-dir=log-dir
sudo ./oft --verbose --default-timeout=6 -i 1@eth1 -i 2@eth2 -i 3@eth3 --disable-ipv6 --switch-ip=192.168.2.197 --host=192.168.2.4 --of-version=1.3 --port=6633 --test-dir=acctonUseDpctl --log-dir=log-dir phase1