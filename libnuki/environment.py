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
import platform
import logging


log = logging.getLogger(__name__)


def set_environment(base_path):
    arch_str = platform.machine()
    system = platform.system()
    nacl_path = ''
    
    log.info('base path: ' + base_path)
    log.info('Architecture: ' + arch_str)
    log.info('System: ' + system)

    if 'linux' in system.lower():

        if 'x86_64' in arch_str:
            nacl_path = "pynacl/linux-x86_64"
            
        elif 'x86' in arch_str:
            raise OSError('This platform is not supported.')

        elif 'armv6' in arch_str:
            nacl_path = "pynacl/linux-armv6l"

        elif 'armv7' in arch_str:
            nacl_path = "pynacl/linux-armv7l"

    elif 'windows' in system.lower():
        raise OSError('This platform is not supported.')

    elif 'darwin' in system.lower():
        raise OSError('This platform is not supported.')

    else:
        raise OSError('This platform is not supported.')
    
    #Make libs available
    sys.path.insert(0, os.path.join(base_path, nacl_path))
    sys.path.insert(0, os.path.join(base_path, "pygatt"))
    sys.path.insert(0, os.path.join(base_path, "cherrypy"))

    