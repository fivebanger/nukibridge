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

import time
import logging
from binascii import hexlify

import nuki_utils as utils
import message as msg

log = logging.getLogger(__name__)


class BLEAdapter(object):

    adapter          = None
    device           = None
    rx_unencrypted   = []
    rx_unencr_seg    = ''
    rx_encrypted     = []
    rx_encr_seg      = ''
    seg_count        = 0
    msg_len          = 0
    msg_len_rx       = 0
    auth_id          = None
    key              = None
    connected        = False
    device           = None
    ps_gdio_handle   = None
    kts_usido_handle = None
    chunk_size       = 18
    get_key          = None
    unencrypted_cb   = None
    encrypted_cb     = None
    
    def __init__(self):
        pass


    def stop(self, error_id):
        raise NotImplementedError(' stop')


    def set_auth_data(self, auth_id, key):
        self.auth_id = auth_id
        self.key = key


    def set_callbacks(self, unencrypted_cb, encrypted_cb):
        self.unencrypted_cb = unencrypted_cb
        self.encrypted_cb   = encrypted_cb
    
    
    def send_encrypted(self, message, wait_for_response=True):
        self.rx_encrypted = []
        self._flush_seg_buffer()
        if( (None == self.auth_id) or (None == self.key) ):
            log.debug('BLE adapter error: no auth id or no key')
        elif( (False == self.connected) or (None == self.kts_usido_handle) ):
            log.debug('BLE adapter error: not connected')
        else:
            message = msg.encrypt_tx(self.auth_id, message, self.key)
            log.debug( 'send encrypted: ' + hexlify(message))
            message = self._format_tx(message)
            self.device.char_write_handle_long(self.kts_usido_handle, message, self.chunk_size, True)


    def send_unencrypted(self, message, wait_for_response=True):
        self.rx_unencrypted = []
        self.rx_unencr_seg  = ''
        if( (False == self.connected) or (None == self.ps_gdio_handle) ):
            log.debug('BLE adapter error: not connected')
        else:
            message = utils.add_crc(message)
            log.debug( 'send unencrypted: ' + hexlify(message))
            message = self._format_tx(message)
            self.device.char_write_handle_long(self.ps_gdio_handle, message, self.chunk_size, True)
    
    
    def unencrypted_segment(self, handle, message):
        if( (5 > len(message)) and ('' == self.rx_unencr_seg) ):
            log.debug( 'BLE adapter error: discard wrong unecrypted segment: ' + hexlify(message))
        else:
            log.debug( 'response unencrypted: ' + hexlify(message))
            self.rx_unencr_seg = self.rx_unencr_seg + message
            retval = utils.verify_crc(self.rx_unencr_seg)
            if( 0 == retval ):
                # message complete
                self.rx_unencrypted.append(self.rx_unencr_seg)
                if( None != self.unencrypted_cb ):
                    self.unencrypted_cb()
                self.rx_unencr_seg  = ''
        return
        

    def encrypted_segment(self, handle, message):
        if( (18 > len(message)) and ('' == self.rx_encr_seg) ):
            log.debug( 'BLE adapter error: discard wrong first segment: ' + hexlify(message))
        else:
            log.debug( 'response encrypted: ' + hexlify(message))
            self.rx_encr_seg = self.rx_encr_seg + message
            self.seg_count   = self.seg_count + 1
            if( 2 == self.seg_count ):
                msg_len = utils.s16_unpack(self.rx_encr_seg[28:30])
                if( msg_len > 255 ):
                    log.debug( 'BLE adapter error: wrong message length: ' + str(msg_len))
                    self._flush_seg_buffer()
                else:
                    # msg_len = len + header data (30bytes)
                    self.msg_len    = msg_len + 30
                    self.msg_len_rx = len(self.rx_encr_seg)
            if( 2 < self.seg_count ):
                self.msg_len_rx = self.msg_len_rx  + len(message)
                if( self.msg_len <= self.msg_len_rx ):
                    # message complete
                    self.rx_encrypted.append(self.rx_encr_seg)
                    if( None != self.encrypted_cb ):
                        self.encrypted_cb()
                    self._flush_seg_buffer()
        return
        
    
    def get_unencrypted(self):
        timeout   = 1
        time_wait = 0
        time_poll = 0.1
        msg_rx    = ''
        
        if( (False == self.connected) or (None == self.ps_gdio_handle) ):
            # inject bridge error
            log.debug( 'BLE adapter error: not connected to GDIO')
            message = self._inject_error_unencrypted(0x55)
            
            return message
        
        while( time_wait < timeout ):
            if( 0 != len(self.rx_unencrypted) ):
                msg_rx = self.rx_unencrypted[0]
                self.rx_unencrypted.remove(msg_rx)
                time_wait = timeout
            else:
                time.sleep(time_poll)
                time_wait = time_wait + time_poll
        
        if( 0 == len(msg_rx) ):
            # inject bridge error
            #hmk log.debug( 'BLE adapter error: unencrypted timeout')
            message = self._inject_error_unencrypted(0x51)        
        else:
            message = self._format_rx(msg_rx)
            log.debug('unencrypted message: ' + hexlify(message))
        
        return message
        
    
    def get_encrypted(self):
        auth_id   = ''
        message   = ''
        decrypted = ''
        msg_rx    = ''
        
        if( (False == self.connected) or (None == self.kts_usido_handle) ):
            # inject bridge error
            log.debug( 'BLE adapter error: not connected to USIDO')
            auth_id, message, decrypted = self._inject_error_encrypted(0x55)
            
            return auth_id, message, decrypted
            
        if( None == self.key ):
            # inject bridge error
            log.debug('BLE adapter error: no key')
            auth_id, message, decrypted = self._inject_error_encrypted(0x53)
        else:
            timeout   = 1
            time_wait = 0
            time_poll = 0.1
            
            while( time_wait < timeout ):
                if( 0 != len(self.rx_encrypted) ):
                    msg_rx = self.rx_encrypted[0]
                    self.rx_encrypted.remove(msg_rx)
                    time_wait = timeout
                else:
                    time.sleep(time_poll)
                    time_wait = time_wait + time_poll
        
        if( 0 == len(msg_rx) ):
            # inject bridge error
            #log.debug( 'BLE adapter error: encrypted timeout')
            auth_id, message, decrypted = self._inject_error_encrypted(0x51)         
        else:
            message = self._format_rx(msg_rx)
            log.debug('encrypted message: ' + hexlify(message))
            auth_id = msg.get_auth_id(message)
            
            if( auth_id != self.auth_id ):
                self.auth_id = auth_id
                if( None != self.get_key ):
                    self.key = self.get_key(auth_id)

            try:
                auth_id, message, decrypted = msg.decrypt_rx(message, self.key)
            except:
                # inject bridge error
                log.debug( 'BLE adapter error: cannot encrypt message')
                auth_id, message, decrypted = self._inject_error_encrypted(0x54)

            retval = utils.verify_crc(decrypted)
            if( 0 != retval ):
                # inject bridge error
                log.debug( 'BLE adapter error: CRC error')
                auth_id, message, decrypted = self._inject_error_encrypted(0x52)

        return auth_id, message, decrypted
        
    
    def _format_tx(self, message):
        data = []
        for byte in message:
            data.append(utils.u8_unpack(byte))
        return data
        
    
    def _format_rx(self, message):
        data = "".join(map(chr, message))
        return data
        
    
    def _flush_seg_buffer(self):
        self.rx_unencr_seg = ''
        self.rx_encr_seg   = ''
        self.seg_count     = 0
        self.msg_len       = 0
        self.msg_len_rx    = 0
        log.debug('clear segmentation buffer')
        return
    
    def _inject_error_encrypted(self, error_id):
        raise NotImplementedError(' _inject_error_encrypted')
