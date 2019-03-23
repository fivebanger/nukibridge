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
import json
import re
import time
import logging
from binascii import hexlify, a2b_hex

from random import randint

dir_path = os.path.dirname(os.path.realpath(__file__))
dir_path, tail = os.path.split(dir_path)

import cherrypy
from nuki import Nuki

log = logging.getLogger(__name__)



# lock states
ls2word  = {0x00: 'uncalibrated', 0x01: 'locked', 0x02: 'unlocking', 0x03: 'unlocked', 0x04: 'locking', 0x05: 'unlatched', 0x06: "unlocked (lock 'n' go active)", 0x07: 'unlatching', 0xFE: 'motor blocked', 0xFF: 'undefined'}
# battery critical
bat2word = {0x00: False, 0x01: True}

PORT = None
#PORT = "/dev/ttyACM0"

  
class NukiBridge(object):
    
    def __init__(self, port, allowed_ip, token, agent):
        self.port       = port
        self.allowed_ip = allowed_ip
        self.token      = token
        self.agent      = agent
        self.bridge_run = False
        return
    
        
    def start(self, block=True, cb_stop=None):     
        # callback on stop  
        self.cb_stop = cb_stop        
        # allow requests from all ip addresses (otherwise only localhost is allowed)
        cherrypy.server.socket_host = '0.0.0.0'
        # set port
        cherrypy.server.socket_port = self.port
        # start server        
        cherrypy.tree.mount(RequestHandler(self.allowed_ip, self.token, self.agent, self.stop), "/")
        cherrypy.engine.start()
        self.bridge_run = True
        
        if( True == block ):
            while(self.bridge_run):
                time.sleep(0.1)
            
        return


    def stop(self):
        if( True == self.bridge_run):
            cherrypy.engine.stop()
            
            if( None != self.cb_stop ):
                self.cb_stop()
                
            self.bridge_run = False
        return
    

class RequestHandler(object):

    """ Cherrypy request handler class. """
    
    def __init__(self, allowed_ip, token, agent, stop=None):
        self.br          = BridgeAdmin()   
        self.allowed_ip  = allowed_ip  
        self.token       = token
        self.agent       = agent
        self.server_stop = stop
        return
    
    
    # Expose the index method through the web. CherryPy will never
    # publish methods that don't have the exposed attribute set to True.
    @cherrypy.expose
    def index(self):
        # CherryPy will call this method for the root URI ("/") and send
        # its return value to the client. Because this is tutorial
        # lesson number 01, we'll just send something really simple.
        # How about...
        self._grant_access(self.token)  
        return """
        <html>
          <head>
          </head>
          <body>
            <form method="get" action="bridgeConfig_html">
              <p>Bridge ID:</p>
              <p><input type="text" value=\""""+str(self.br.get_id())+"""\" name="bridgeId" /></p>
              <p>Bridge Name:</p>
              <p><input type="text" value=\""""+self.br.get_name()+"""\" name="bridgeName" /></p>
              <button type="submit">Change</button><br><br><br>
            </form>
            <form method="get" action="nukiPair_html">
              <p>Connect to Nuki SmartLock:</p>
              <p><input type="text" value="Nuki Name" name="nukiName" /></p>
              <p><input type="text" value="00:00:00:00:00:00" name="nukiMac" /></p>
              <button type="submit">Connect</button><br><br><br>
            </form>
            <form method="get" action="list_html">
              <p>List all connected Nuki SmartLocks</p>
              <button type="submit">List Nukis</button><br>
            </form>
          </body>
        </html>"""
    
    
    @cherrypy.expose
    def stop(self, token=None):
        self._grant_access(token) 
        
        if( None != self.server_stop ):
            self.server_stop()
            
        return 'bye'
    
    
    @cherrypy.expose
    def bridgeInfo(self, token=None):
        self._grant_access(token) 
        
        br_id   = self.br.get_id()
        br_name = self.br.get_name()
        
        result = ({'bridgeId': br_id, 'bridgeName': br_name})
        
        return json.dumps(result)
    
    
    @cherrypy.expose
    def bridgeConfig(self, bridgeId, bridgeName, token=None):
        self._grant_access(token) 
        
        try:
            bridgeId = int(bridgeId)
        except:
            raise cherrypy.HTTPError(400)
        
        if( 0xFFFFFFFF < bridgeId ):
            raise cherrypy.HTTPError(400)
        
        try:
            bridgeName.decode('utf-8')
        except UnicodeError:
            raise cherrypy.HTTPError(400)
        
        retval = self.br.set_br_data(bridgeId, bridgeName)
        
        if( True == retval ):
            br_id   = self.br.get_id()
            br_name = self.br.get_name()
            
            result = ({'bridgeId': br_id, 'bridgeName': br_name, 'success': retval})
        else:
            err_code, err_cmd = self.br.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
            
        return json.dumps(result)
        
        
    @cherrypy.expose
    def bridgeConfig_html(self, bridgeId, bridgeName):
        self._grant_access(self.token)   
        
        retval = True
        result = ''
        response = 'void'
    
        result = self.br.get_sl_list()
        
        if( 0 != len(result) ):
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>Changing bridge configuration is not allowed. A SmartLock is already connected to the bridge.</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response
        
        try:
            bridgeId = int(bridgeId)
        except:
            retval = False
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>Only numeric values for Bridge ID allowed."</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response
        
        if( 0xFFFFFFFF < bridgeId ):
            retval = False
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>Bridge ID is out of rang: Only values between 0 and 4294967295 allowed.</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response
        
        try:
            bridgeName.decode('utf-8')
        except UnicodeError:
            retval = False
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>Bridge Name contains invalid characters."</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response

        if( True == retval ):
            retval  = self.br.set_br_data(bridgeId, bridgeName)
            br_id   = self.br.get_id()
            br_name = self.br.get_name()
            
        if( True == retval ):    
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>New Bridge ID: """ + str(br_id) + """</p>
                  <p>New Bridge Name : """ + br_name + """</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            
        return response
                
    
    
    @cherrypy.expose
    def list(self, token=None):
        self._grant_access(token) 
                     
        result = self.br.get_sl_list()
        return json.dumps(result)
    
    
    @cherrypy.expose
    def list_html(self):
        self._grant_access(self.token) 
                     
        result = self.br.get_sl_list()
        
        if( 0 == len(result) ):
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>No Nuki Smartlocks connected to Bridge.</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
        else:
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">"""

            for sl in result:                
                sl_list_line = '<p>Nuki-ID: '+ str(sl['nukiId']) + ', Nuki-Name: ' + sl['name'] + '</p>'  
                response = response + sl_list_line
                  
            response = response + """
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
        
        return response
    
    
    @cherrypy.expose
    def lockState(self, nukiId, token=None):
        self._grant_access(token) 
        
        n = self._get_nuki_by_id(nukiId)
        
        retval, nuki_state, lock_state, trigger, bat = n.get_states()
        
        if( True == retval ):
            bat = bat2word[bat]
            lock_state_name = ls2word[lock_state]
            result = ({'state': lock_state, 'stateName': lock_state_name, 'batteryCritical': bat, 'success': retval})
        else:
            err_code, err_cmd = n.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
        
        return json.dumps(result)
    
    
    @cherrypy.expose
    def lockAction(self, nukiId, action, token=None):
        self._grant_access(token) 
                  
        n = self._get_nuki_by_id(nukiId) 
        
        action = int(action)
        if( 5 < action ):
            raise cherrypy.HTTPError(400)
        
        retval, bat = n.lock_action(action)
        
        if( True == retval ):
            bat    = bat2word[bat]
            result = ({'success': retval, 'batteryCritical': bat})
        else:
            err_code, err_cmd = n.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
        
        return json.dumps(result)
    
    
    @cherrypy.expose
    def nukiPair(self, nukiName, nukiMac, token=None):
        self._grant_access(token)   
    
        retval = self.br.check_sl_name(nukiName)
            
        if( False == retval ):
            raise cherrypy.HTTPError(400)
        
        retval = self._check_mac_format(nukiMac)
            
        if( False == retval ):
            raise cherrypy.HTTPError(400)
        
        n = self._get_nuki(nukiMac)
        retval, sl_auth_id, sl_uuid, sl_key = n.authorize()
        
        if( True == retval ):
            retval, sl_id = self.br.add_sl(sl_auth_id, sl_uuid, sl_key, nukiMac, nukiName)
            result = ({'success': retval, 'nukiId': sl_id, 'name': nukiName})
        else:
            err_code, err_cmd = n.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
            
        return json.dumps(result)
    
    
    @cherrypy.expose
    def nukiPair_html(self, nukiName, nukiMac, token=None):
        self._grant_access(token)   
    
        retval = self.br.check_sl_name(nukiName)
        
        if( False == retval ):
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>\"""" + nukiName + """\" is already connected.</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response
        
        retval = self._check_mac_format(nukiMac)
            
        if( False == retval ):
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>Wrong MAC address format: Use 00:00:00:00:00:00</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            return response
        
        n = self._get_nuki(nukiMac)
        retval, sl_auth_id, sl_uuid, sl_key = n.authorize()
        
        if( True == retval ):
            retval, sl_id = self.br.add_sl(sl_auth_id, sl_uuid, sl_key, nukiMac, nukiName)
            
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>New Nuki SmartLock connected:</p>
                  <p>Nuki-ID: """+str(sl_id)+""", Nuki-Name: """+nukiName+"""</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
        else:
            response = """
            <html>
              <head>
              </head>
              <body>
                <form method="get" action="index">
                  <p>New Nuki SmartLock could not be connected.</p>
                  <button type="submit">Back</button><br>
                </form>
              </body>
            </html>"""
            
        return response
    
    
    @cherrypy.expose
    def updateTime(self, nukiId, nukiPin, token=None):
        self._grant_access(token) 
        
        try:
            nukiPin = int(nukiPin)
        except:
            raise cherrypy.HTTPError(400)
        
        if( 0xFFFF < nukiPin ):
            raise cherrypy.HTTPError(400)
        
        n = self._get_nuki_by_id(nukiId)
        retval = n.update_time(nukiPin)
        
        if( True == retval ):
            retval, nuki_state, lock_state, trigger, bat = n.get_states()
            
        if( True == retval ):
            bat = bat2word[bat]
            result = ({'success': retval, 'batteryCritical': bat})
        else:
            err_code, err_cmd = n.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
            
        return json.dumps(result)
    
    
    @cherrypy.expose
    def batteryState(self, nukiId, token=None):
        self._grant_access(token) 
        
        n = self._get_nuki_by_id(nukiId)
        retval, bat, battery_voltage = n.get_battery_report()
            
        if( True == retval ):
            bat = bat2word[bat]
            result = ({'success': retval, 'batteryVoltage': battery_voltage, 'batteryCritical': bat})
            return json.dumps(result)
        else:
            err_code, err_cmd = n.get_error()
            result = ({'success': retval, 'errorCode': err_code, 'errorCmd': err_cmd})
            
        return json.dumps(result)
    
    
    def _get_nuki_by_id(self, sl_id):   
        br_id   = self.br.get_id()
        br_name = self.br.get_name()

        sl_auth_id, sl_key, sl_uuid, mac_addr, sl_name = self.br.get_sl(int(sl_id))
        if( '' != sl_auth_id ):
            smart_lock = Nuki(br_id, br_name, mac_addr, sl_auth_id, sl_key, port=PORT)
        else:
            raise cherrypy.HTTPError(404)

        return smart_lock
    
    
    def _get_nuki(self, sl_mac_addr):   
        br_id   = self.br.get_id()
        br_name = self.br.get_name()
                     
        smart_lock = Nuki(br_id, br_name, sl_mac_addr, port=PORT)

        return smart_lock
    
    
    def _grant_access(self, token):
        # only known ip addresses allowed (0.0.0.0 means any IP allowed)
        ip = cherrypy.request.headers["Remote-Addr"]        
        if( (ip not in self.allowed_ip) and ('0.0.0.0' not in self.allowed_ip) ):
            raise cherrypy.HTTPError(403)
        
        # only request with valid token allowed
        if( None != self.token ):
            if( token != self.token ):
                raise cherrypy.HTTPError(403)
        
        # only request with valid HTTP header 'user-agent' allowed
        if( None != self.agent ):
            agent = cherrypy.request.headers["user-agent"]
            if( agent != self.agent ):
                raise cherrypy.HTTPError(403)
        
        return
    
    
    def _check_mac_format(self, mac_addr):
        
        if( re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_addr.lower()) ):
            return True
        
        return False
    
    
class BridgeAdmin(object):
    
    def __init__(self, br_id=None, br_name=None, data_dir=None):
        self.list     = []
        self.dir      = ''
        self.file     = 'bridge.jsn'
        self.err_code = 0xFF
        self.command  = 0xFFFF
        
        if( None == data_dir ):
            data_dir  = 'data'
            self.dir = os.path.join(dir_path, data_dir)
        
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
    
        data_file=os.path.join(self.dir, self.file)
        try:  
            fh = open(data_file, 'r')
            result=json.loads( fh.read() )
            self.list = result
        except:
            log.debug('Cannot load list')
            self._create_list(br_id, br_name)
    
        return
         
        
    def check_sl_name(self, sl_name):
        
        retval = True
        
        if( 0 == self.list['sl_total']):
            return retval
        
        sl_list  = self.list['sl_list']
    
        for item in sl_list:            
            if( sl_name == item['name'] ):
                retval = False
    
        return retval
    
    
    def set_br_data(self, br_id, br_name):
        
        retval = True
        
        if ( 0 != self.list['sl_total'] ):
            # cannot change in case a SL is already associated with the current bridge data
            self.err_code = 0x50
            self.command  = 0xFFFF
            retval = False
        else:
            self.list['br_data']['br_id']   = br_id
            self.list['br_data']['br_name'] = br_name
            self._save_list()
            
        return retval
    
    
    def get_id(self):
        return self.list['br_data']['br_id']
    
    
    def get_name(self):
        return self.list['br_data']['br_name']
        
        
    def get_sl_list(self):
        return self.list['sl_list']
    
    
    def get_sl(self, sl_id):

        sl_auth_id  = ''
        sl_key      = ''
        sl_uuid     = ''
        sl_name     = ''
        sl_mac_addr = ''
            
        if( (0 != sl_id) and ( sl_id <= self.list['sl_total']) ):        
            sl_id = sl_id-1
            sl_data     = self.list['sl_data']
            sl_auth_id  = sl_data[sl_id]['sl_auth_id']
            sl_key      = sl_data[sl_id]['sl_key']
            sl_uuid     = sl_data[sl_id]['sl_uuid']
            sl_name     = sl_data[sl_id]['name']
            sl_mac_addr = sl_data[sl_id]['sl_mac_addr']
        
            sl_uuid    = a2b_hex(sl_uuid)
            sl_key     = a2b_hex(sl_key)
            
        return sl_auth_id, sl_key, sl_uuid, sl_mac_addr, sl_name
    
    
    def add_sl(self, sl_auth_id, sl_uuid, sl_key, sl_mac_addr, sl_name=''):
        
        sl_list  = self.list['sl_list']
        sl_data  = self.list['sl_data']
        br_data  = self.list['br_data']
        sl_total = self.list['sl_total']
        sl_id = 0
        
        # check for unique name
        retval = self.check_sl_name(sl_name)
        
        if( False == retval ):
            return retval, sl_id

        sl_id = sl_total + 1
        sl_total = sl_total + 1
        
        if( '' == sl_name):
            sl_name = 'Nuki_'+str(sl_id)
        
        sl_uuid = hexlify(sl_uuid)
        sl_key  = hexlify(sl_key)
        
        sl_list.append({'nukiId': sl_id, 'name': sl_name})
        sl_data.append({'nukiId': sl_id, 'name': sl_name, 'sl_mac_addr': sl_mac_addr, 'sl_auth_id': sl_auth_id, 'sl_key': sl_key, 'sl_uuid': sl_uuid})
    
        self.list = ({'sl_total': sl_total, 'br_data': br_data, 'sl_list': sl_list, 'sl_data': sl_data})
        self._save_list()
        
        return retval, sl_id
    
    
    def remove_sl(self, sl_name):
        
        retval = False
        
        sl_list  = self.list['sl_list']
        sl_data  = self.list['sl_data']
        br_data  = self.list['br_data']
        sl_total = self.list['sl_total']
        
        # remove entry
        i = 0
        for item in sl_list:            
            if( sl_name == item['name'] ):
                del sl_list[i]
                del sl_data[i]
                sl_total = sl_total - 1
                retval = True
                break
            i = i+1
            
        # renumber complete list
        if (True == retval ):
            i = 0
            for item in sl_list:            
                sl_list[i]['nukiId'] = i+1
                sl_data[i]['nukiId'] = i+1
                i = i+1
                
                self.list = ({'br_data': br_data, 'sl_total': sl_total, 'sl_list': sl_list, 'sl_data': sl_data})
                self._save_list()
        
        return retval
    
    
    def get_error(self):
        err_code  = self.err_code
        err_cmd   = self.command
        return err_code, err_cmd
    
    
    def _create_list(self, br_id, br_name):

        sl_list = []
        sl_data = []
        sl_total = 0
        
        if( None == br_id ):
            br_id = randint(0x00000000, 0xFFFFFFFF)
        if( None == br_name ):
            br_name = 'Bridge'
            
        br_data = ({'br_id': br_id, 'br_name': br_name})
    
        self.list = ({'br_data': br_data, 'sl_total': sl_total, 'sl_list': sl_list, 'sl_data': sl_data})
        self._save_list()
        
        return 
    
    
    def _save_list(self):
    
        data_file=os.path.join(self.dir, self.file)
        fh = open(data_file, 'w')
        json_list = json.dumps(self.list)
        fh.write(json_list)
        fh.close()
            
        return



"""
General error codes

0xFD ERROR_BAD_CRC
0xFE ERROR_BAD_LENGTH
0xFF ERROR_UNKNOWN



Pairing service error codes

0x10 P_ERROR_NOT_PAIRING
0x11 P_ERROR_BAD_AUTHENTICA
0x12 P_ERROR_BAD_PARAMETER
0x13 P_ERROR_MAX_USER



Keyturner service error codes

0x20 K_ERROR_NOT_AUTHORIZED
0x21 K_ERROR_BAD_PIN
0x22 K_ERROR_BAD_NONCE
0x23 K_ERROR_BAD_PARAMETER
0x24 K_ERROR_INVALID_AUTH_ID
0x25 K_ERROR_DISABLED
0x26 K_ERROR_REMOTE_NOT_ALLOWED
0x27 K_ERROR_TIME_NOT_ALLOWED
0x40 K_ERROR_AUTO_UNLOCK_TOO_REC
0x41 K_ERROR_POSITION_UNKNOWN
0x42 K_ERROR_MOTOR_BLOCKED
0x43 K_ERROR_CLUTCH_FAILURE
0x44 K_ERROR_MOTOR_TIMEOUT
0x45 K_ERROR_BUSY



Status codes

0x00 COMPLETE
0x01 ACCEPTED


Bridge error codes

0x50 B_ERROR_ALREADY_INIT
0x51 B_ERROR_MSG_TIMEOUT
0x52 B_ERROR_BAD_CRC
0x53 B_ERROR_NO_KEY
0x54 B_ERROR_ENCRYPT
0x55 B_ERROR_NOT_CONNECTED
"""
