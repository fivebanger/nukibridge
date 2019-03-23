# Copyright 2016 Fivebanger
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

import os.path
import sys

#Make libnuki available
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(dir_path, "libnuki"))

from environment import set_environment
set_environment(dir_path)

from bridge import NukiBridge


"""
Specify the port the Nuki Bridge uses
"""
nb_port = 8080


"""
Specify a list of allowed IP addresses. Requests from hosts using another IP address are replied with HTTP error 403
Set nb_allowed_ip = ('0.0.0.0') if any IP address shall have access.

Examples:
nb_allowed_ip = ('127.0.0.1', '192.168.162.42')    # localhost and 192.168.162.42
nb_allowed_ip = ('0.0.0.0')                        # all hosts
nb_allowed_ip = ('127.0.0.1')                      # local host only
"""
nb_allowed_ip = ('0.0.0.0')


"""
Specify a token which needs to be sent along with the HTTP request.
Set nb_token = None if no token shall be used.

Examples:
nb_token = None        # no need to send a token along with the HTTP request
nb_token = 'a34f42'    # send &token=a34f42 as parameter along with the HTTP request
"""
nb_token = None


"""
Specify a user-agent which needs to be sent along with the HTTP header of the request.
To send a proper user-agent, HTTP header needs to be manipulated (standard web browser needs header manipulation)
Set nb_header = None if no header shall be used. 

Examples:
nb_agent = None                # no user-agent needs to be sent along with the HTTP header
nb_agent = 'MyFancyAgent'      # user-agent = MyFancyAgent needs to be sent along with the HTTP header
"""
nb_agent = None


"""
Optional parameter for NukiBridge.start()

Usage:
nb_block = True                # blocking execution of the NukiBridge (default)
nb_block = False               # non-blocking execution of the NukiBridge
"""
nb_block = True


"""
http API usage:

http://localhost:8080
parameter: -


http://localhost:8080/bridgeInfo
parameter: -
return : {"bridgeId": 2736774877, "bridgeName": "Bridge"}


http://localhost:8080/bridgeConfig?bridgeId=2&bridgeName=Bridge
parameter: bridgeId: 0..4294967295
parameter: bridgeName: ASCII, UTF-8
return: {"bridgeId": 2, "bridgeName": "Bridge"}


http://localhost:8080/list
parameter: -
return: [{"nukiId": 1, "name": "Test_1"}, {"nukiId": 2, "name": "Test_2"}]


http://localhost:8080/nukiPair?nukiName=Test_1
parameter: nukiName: ASCII
return: {"nukiId": 1, "name": "Test_1", "success": true}


http://localhost:8080/lockState?nukiId=1
parameter: nukiId: 1..nn
return: {"state": 0, "stateName": "uncalibrated", "success": true, "batteryCritical": false}
stateName: 0: uncalibrated
           1: locked
           2: unlocked
           3: unlocked (lock 'n' go)
           4: unlatched
           5: locking
           6: unlocking
           7: unlatching
           254: motor blocked, 255: undefined)


http://localhost:8080/lockAction?nukiId=1&action=1
parameter: nukiId: 1..nn
parameter: action: 1..5
action     1: unlock
           2: lock
           3: unlatch
           4: lock 'n' go
           5: lock 'n' go with unlatch

return: {"success": true, "batteryCritical": false}


http://localhost:8080/updateTime?nukiId=1&nukiPin=1234
parameter: nukiId: 1..nn
parameter: nukiPin: Pin given by the Nuki configuration
return: {"success": true, "batteryCritical": "false"}


http://localhost:8080/batteryState?nukiId=1
parameter: nukiId: 1..nn
return: {"batteryVoltage": 0, "success": true, "batteryCritical": false}



http://localhost:8080
http://localhost:8080/updateTime?nukiId=1&nukiPin=1234&token=a34f42
http://localhost:8080/batteryState?nukiId=1&token=a34f42
http://localhost:8080/bridgeConfig?bridgeId=2&bridgeName=Bridge&token=a34f42
http://localhost:8080/bridgeInfo&token=a34f42
http://localhost:8080/nukiPair?nukiName=Test_1&token=a34f42
http://localhost:8080/list&token=a34f42
http://localhost:8080/lockState?nukiId=1&token=a34f42
http://localhost:8080/lockAction?nukiId=1&action=1&token=a34f42
"""


if __name__ == '__main__':
    nb = NukiBridge(nb_port, nb_allowed_ip, nb_token, nb_agent)
    nb.start(nb_block)

    print'end'
