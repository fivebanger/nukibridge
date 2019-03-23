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

import pygatt
import logging
import nuki_utils as utils

import command as cmd
from ble_adapter import BLEAdapter

log = logging.getLogger(__name__)


kt_init_service_uuid    = 'a92ee000-5501-11e4-916c-0800200c9a66'

kt_pairing_service_uuid = 'a92ee100-5501-11e4-916c-0800200c9a66'
ktps_gdio_uuid          = 'a92ee101-5501-11e4-916c-0800200c9a66'

kt_service_uuid         = 'a92ee200-5501-11e4-916c-0800200c9a66'
kts_gdio_uuid           = 'a92ee201-5501-11e4-916c-0800200c9a66'
kts_usdio_uuid          = 'a92ee202-5501-11e4-916c-0800200c9a66'


class BLEClient(BLEAdapter):
    
    def __init__(self, auth_id=None, key=None, port=None):
        self.auth_id = auth_id
        self.key     = key
        #self.adapter = pygatt.GATTToolBackend()
        self.adapter = pygatt.BGAPIBackend(serial_port=port)
        """
        reset_on_start = True
        retries        = 5
        while( retries ):
            retval = self.adapter.start(reset_on_start=reset_on_start)
            if( None == retval ):
                log.error('BLEAdapter error: cannot connect to device')
                retries = retries - 1
                self.connected = False
            else:
                retries = 0
                self.connected = True
        """
        reset_on_start = True
        try:
            #retval = self.adapter.start(reset_on_start=reset_on_start)
            self.adapter.start()
            self.connected = True
        except: 
            log.error('BLEAdapter error: cannot start adapter')
            self.connected = False
        return
    
    
    def scan(self):
        return self.adapter.scan()
    
    
    def connect(self, mac_addr):
        
        if( False == self.connected ):
            return
            
        timeout = 20
        self.device = self.adapter.connect(mac_addr, timeout)

        try:
            self.ps_gdio_handle = self.device.get_handle(ktps_gdio_uuid)
            self.device.subscribe(ktps_gdio_uuid, self.unencrypted_segment, True)
        except:
            #un-encrypted data service
            log.debug('BLEAdapter error: cannot subscribe to KTPS GDIO')
            self.ps_gdio_handle = None

        try:
            #encrypted data service
            self.kts_usido_handle = self.device.get_handle(kts_usdio_uuid)
            self.device.subscribe(kts_usdio_uuid, self.encrypted_segment, True)
        except:
            log.debug('BLEAdapter error: cannot subscribe to KTS USDIO')
            self.kts_usido_handle = None
        return
    
    
    def stop(self):
        try:
            self.device.unsubscribe(ktps_gdio_uuid)
        except:
            pass
        try:
            self.device.unsubscribe(kts_usdio_uuid)
        except:
            pass
        try:
            self.device.disconnect()
        except:
            pass
        try:
            self.adapter.stop()
        except:
            pass
        return
    
    
    def discover(self, timeout=5):
        mac_addr = ''
        name = ''
        return mac_addr, name


    def _inject_error_encrypted(self, error_id, cmd_id=0xFFFF, auth_id=0xFFFFFFFF):
        error     = error_id
        cmd_id    = cmd_id
        message   = cmd.error_bridge(error, cmd_id)
        decrypted = utils.pack_u32(auth_id) + message
        decrypted = utils.add_crc(decrypted)
        
        return auth_id, message, decrypted
    

    def _inject_error_unencrypted(self, error_id, cmd_id=0xFFFF):
        error   = error_id
        message = cmd.error_bridge(error, cmd_id)
        message = utils.add_crc(message)
        
        return message
