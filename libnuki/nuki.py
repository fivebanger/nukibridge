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
from binascii import hexlify, a2b_hex

import nacl.bindings
import nuki_utils as utils
import command as cmd
#from bt_mock import BluetoothMock as BLEClient
from ble_client import BLEClient

log = logging.getLogger(__name__)


class Nuki(object):

    def __init__(self, bridge_id, bridge_name, mac_addr, auth_id=0, key='', port=None):
        self.id_type   = 0x01
        self.bridge_id = bridge_id
        self.name      = bridge_name
        self.mac_addr  = mac_addr
        self.auth_id   = auth_id
        self.uuid      = ''
        self.key       = key
        self.err_code  = 0xFF
        self.command   = 0xFFFF
        self.port      = port
        return
    
    
    def authorize(self):
        
        retval = True
        auth_id = 0
        uuid = ''
        key = ''
        nonce_abf = None

        bt = BLEClient(port=self.port)
        bt.connect(self.mac_addr)
        
        #==============================================================================
        # Authentication process
        #==============================================================================
        
        # request sl public key
        log.debug( 'request SL public key' )
        message = cmd.public_key_request()
        bt.send_unencrypted(message)
        
        # receive sl public key
        message = bt.get_unencrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        if( (0x0003 == cmd_id) and (True == retval) ):
            log.debug( 'SL public key received' )
            sl_public_k = cmd.public_key_decode(message)
            
            # generate keys
            log.debug( 'generating key' )
            cl_public_k, cl_private_k = self._generate_keypair()
            self.key = self._generate_kdf1(cl_private_k, sl_public_k)
            
            # send own public key
            log.debug( 'send own public key' )
            message = cmd.public_key(cl_public_k)
            bt.send_unencrypted(message)
            
            # receive sl challenge 1
            message = bt.get_unencrypted()
            cmd_id = cmd.get_cmd_id(message)
        else:
            log.debug( 'Nuki error: no public key received' )
            retval = False
        
        if( (0x0004 == cmd_id) and (True == retval) ):
            log.debug( 'SL nonce_k received' )
            nonce_k = cmd.challenge_decode(message)
                
            #send authenticator
            log.debug( 'send authenticator' )
            message = cmd.authenticator(cl_public_k, sl_public_k, nonce_k, self.key)
            bt.send_unencrypted(message)
            
            # receive sl challenge 2
            message = bt.get_unencrypted()
            cmd_id = cmd.get_cmd_id(message)
        else:
            log.debug( 'Nuki error: no nonce nonce_k received' )
            retval = False
        
        if( (0x0004 == cmd_id) and (True == retval) ):
            log.debug( 'SL nonce_k received' )
            nonce_k = cmd.challenge_decode(message)
        
            # send authorization data
            log.debug( 'send authorization data' )
            nonce_abf = nacl.utils.random(32)
            message = cmd.authorization_data(self.id_type, self.bridge_id, self.name, nonce_abf, nonce_k, self.key)
            bt.send_unencrypted(message)
            
            # receive authorization id
            message = bt.get_unencrypted()
            cmd_id = cmd.get_cmd_id(message)
        else:
            log.debug( 'Nuki error: no nonce_k received' )
            retval = False
        
        if( (0x0007 == cmd_id) and (True == retval) ):
            # cl verifies authorization id
            log.debug( 'SL authorization id received' )
            verify = self._auth_message(message, nonce_abf, self.key)
            if( 0 != verify ):
                error_code = 0x11
                command = cmd.get_cmd_id(message)
                message = cmd.error_bridge(error_code, command)
                cmd_id  = cmd.get_cmd_id(message)
        else:
            log.debug( 'Nuki error: no authorization id received' )
            retval = False
            
        if( (0x0007 == cmd_id) and (True == retval) ):
            log.debug( 'SL authorization id verified' )
            self.auth_id, uuid, nonce_k = cmd.authorization_id_decode(message)
            self.uuid = uuid
            
            log.debug( 'Authentication ID: ' + hex(self.auth_id) )
            log.debug( 'UUID: ' + hexlify(self.uuid) )
        
            # send authorization id confirmation
            log.debug( 'send authorization id confirmation' )
            message = cmd.authorization_id_confirmation(self.auth_id, nonce_k, self.key)
            bt.send_unencrypted(message)
            
            # receive status ok
            message = bt.get_unencrypted()
            cmd_id = cmd.get_cmd_id(message)
        else:
            log.debug( 'Nuki error: authorization id verification' )
            retval = False
        
        if( (0x000E == cmd_id) and (True == retval) ):
            # Nuki states received
            log.debug( 'SL status received' )
            status = cmd.status_decode(message)
            log.debug( 'status: ' + str(hex(status)) )
        else:
            log.debug( 'Nuki error: no status received' )
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()
            
        return retval, self.auth_id, uuid, self.key
    
    
    def lock_action(self, lock_action, auto_Unlock=False, force_unlock=False):
        retval = True
        bat    = 0

        bt = BLEClient(self.auth_id, self.key, self.port)
        bt.connect(self.mac_addr)
        
        flags = 0x00
        if( auto_Unlock == True ):
            flags |= 0x01
        if( force_unlock == True ):
            flags |= 0x02
            
        #==============================================================================
        # Lock action
        #==============================================================================
        
        # send challenge request
        log.debug('request challenge' )
        message = cmd.challenge_request(self.auth_id, self.key)
        bt.send_encrypted(message)
        
        # receive sl challenge
        auth_id, message, decrypted = bt.get_encrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        if( (0x0004 == cmd_id) and (True == retval) ):
            log.debug('SL challenge received' )
            nonce_k = cmd.challenge_decode(message)
            
            # send lock action
            log.debug('send lock action' )
            message = cmd.lock_action(self.auth_id, lock_action, self.bridge_id, flags, nonce_k)
            bt.send_encrypted(message)
            
            # receive status accepted
            auth_id, message, decrypted = bt.get_encrypted()
            cmd_id = cmd.get_cmd_id(message)
        else:
            log.debug('Nuki error: no challenge received' )
            retval = False

        if( (0x000E == cmd_id) and (True == retval) ):
            # status received
            status = cmd.status_decode(message)
            
            if( 0x01 == status):
                # lock action accepted
                log.debug('lock action accepted' )
                
                retries = 20
                while( retries ):
                    log.debug('wait for lock action complete' )
                    auth_id, message, decrypted = bt.get_encrypted()
                    cmd_id = cmd.get_cmd_id(message)
                    
                    if( 0x000C == cmd_id ):
                        # Nuki state received
                        log.debug('Nuki state received' )
                        n_stat, l_stat, trigger, sl_time, sl_time_z, bat = cmd.nuki_states_decode(message)
                    elif( 0x000E == cmd_id ):
                        # status received
                        retries = 0
                    elif( 0x0012 == cmd_id ):
                        # error received
                        retries = 0
                    else: 
                        retries = retries - 1
                     
                if( 0x000E == cmd_id ):
                    status = cmd.status_decode(message)                        
                    if( 0x00 == status):
                        # lock status complete
                        log.debug('lock status complete' )
                        retval = True
                    else:
                        # lock status not complete
                        log.debug('Nuki error: lock status not complete' )
                        retval = False
                else:
                    # no lock status received
                    log.debug('Nuki error: no lock status received' )
                    retval = False
                    
            else:
                # lock action not accepted
                log.debug('Nuki error: lock action not accepted' )
                retval = False
        else:
            log.debug('Nuki error: no status received' )
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()
        
        return retval, bat
    
    
    def get_config(self):
        retval    = True
        sl_config = {}

        #==============================================================================
        # Request SL config
        #==============================================================================
        bt = BLEClient(self.auth_id, self.key, self.port)
        bt.connect(self.mac_addr)
        
        # send request SL states
        log.debug('request SL states' )
        message = cmd.config_request_encode()
        bt.send_encrypted(message)
        
        # receive SL states
        auth_id, message, decrypted = bt.get_encrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        if( (0x0015 == cmd_id) and (True == retval) ):
            # SL state received
            log.debug('SL config received' )
            sl_config = cmd.config_decode(message)
        else:
            # no SL state received
            log.debug('Nuki error: no Nuki config received' )
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()
        return retval, sl_config
    
    
    def get_states(self):
        retval     = True
        nuki_state = 0
        lock_state = 0
        trigger    = 0
        bat        = 0

        #==============================================================================
        # Request SL status
        #==============================================================================
        bt = BLEClient(self.auth_id, self.key, self.port)
        bt.connect(self.mac_addr)
        
        # send request SL states
        log.debug('request SL states' )
        message = cmd.nuki_states_request()
        bt.send_encrypted(message)
        
        # receive SL states
        auth_id, message, decrypted = bt.get_encrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        if( (0x000C == cmd_id) and (True == retval) ):
            # SL state received
            log.debug('SL state received' )
            nuki_state, lock_state, trigger, sl_time, sl_time_z, bat = cmd.nuki_states_decode(message)
        else:
            # no SL state received
            log.debug('Nuki error: no Nuki state received' )
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()
            
        return retval, nuki_state, lock_state, trigger, bat
    
    
    def update_time(self, sec_pin):
        retval = True

        bt = BLEClient(self.auth_id, self.key, self.port)
        bt.connect(self.mac_addr)
        
        # send challenge request
        message = cmd.challenge_request(self.auth_id, self.key)
        bt.send_encrypted(message)
        
        # receive sl challenge
        auth_id, message, decrypted = bt.get_encrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        # send update time
        if( (0x0004 == cmd_id) and (True == retval) ):
            nonce_k = cmd.challenge_decode(message)
            time = utils.get_time()
            message = cmd.update_time(time, nonce_k, sec_pin)
            bt.send_encrypted(message)
            
            # receive status accepted
            auth_id, message, decrypted = bt.get_encrypted()
            cmd_id = cmd.get_cmd_id(message)
        
        if( (0x000E == cmd_id) and (True == retval) ):
            status = cmd.status_decode(message)
            log.debug( 'Status: ' +str(hex(status)) )
            
            if( 0x01 == status):
                log.debug( 'Todo: update_time' )    #hmk TODO:
        else:
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()

        return retval
    
    
    def get_battery_report(self):
        retval = True
        critical_battery_state = 0
        battery_voltage        = 0

        bt = BLEClient(self.auth_id, self.key, self.port)
        bt.connect(self.mac_addr)
        
        # send battery report request
        log.debug('request battery report' )
        message = cmd.battery_report_request()
        bt.send_encrypted(message)
        
        # receive battery report
        auth_id, message, decrypted = bt.get_encrypted()
        cmd_id = cmd.get_cmd_id(message)
        
        if( (0x0011 == cmd_id) and (True == retval) ):
            # battery report received
            log.debug('SL battery report received' )
            bat_drain, bat_voltage, bat_state = cmd.battery_report_decode(message)
            log.debug( 'Battery drain: ' +str(hex(bat_drain)) )
            log.debug( 'Battery voltage: ' +str(hex(bat_voltage)) )
            log.debug( 'Battery state: ' +str(hex(bat_state)) )
        else:
            # no battery report received
            log.debug('Nuki error: no SL battery report received' )
            retval = False
        
        if( False == retval):
            # error handler
            log.debug( 'Nuki error handler' )
            self._err_handler(cmd_id, message)
            
        bt.stop()
            
        return retval, critical_battery_state, battery_voltage
    
    
    def get_error(self):
        err_code  = self.err_code
        err_cmd   = self.command
        return err_code, err_cmd
    
    
    def _err_handler(self, cmd_id, message):
        self.err_valid = True
        
        if( 0x0012 == cmd_id ):
            # error received from SL
            self.err_code, self.command = cmd.error_report_decode(message)
        elif( 0x8012 == cmd_id ):
            # Bridge error
            self.err_code, self.command = cmd.error_bridge_decode(message)
        else:
            # Unknown
            self.err_code = 0xFF
            self.command  = 0xFFFF
        return
    
    
    def _auth_message(self, message, nonce_k, secret_key):   
        auth_h = message[2:34]
        msg_v  = message[34:(len(message)-2)] + nonce_k
        return nacl.bindings.crypto_auth_hmacsha256_verify(auth_h, msg_v, secret_key)
    
    
    def _generate_keypair(self):
        # generate own key-pair
        public_k, private_k = nacl.bindings.crypto_box_keypair()
        return public_k, private_k
    
    
    def _generate_kdf1(self, private_k, shared_key):
        # calculate dh1 key
        dh1_key = nacl.bindings.crypto_scalarmult_curve25519(private_k, shared_key)
        #generate long term secret kdf1 key
        msg_lts = a2b_hex(b'00000000000000000000000000000000')
        sigma = 'expand 32-byte k'
        secret_key = nacl.bindings.crypto_core_hsalsa20(msg_lts, dh1_key, sigma)
        return secret_key
        
