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

from binascii import hexlify

import nuki_utils as utils
import nacl.secret


def encrypt_tx(auth_id, message, key, nonce = ''):
        auth_id   = utils.pack_u32(auth_id)
        pdata     = auth_id + message
        pdata     = utils.add_crc(pdata)
        encrypted = encrypt( pdata, key, nonce )
        nonce     = encrypted[:24]
        pdata     = encrypted[24:]
        length    = len(pdata)
        length    = utils.pack_u16(length)
        message   = nonce + auth_id + length + pdata
        return message 

def encrypt(message, key, nonce):
    box = nacl.secret.SecretBox(key)
    if( '' == nonce ):
        nonce = nacl.utils.random(24)
    encrypted = box.encrypt(message, nonce)
    return encrypted

def decrypt_rx(adata, key):
    nonce     = adata[:24]
    message   = adata[30:]
    decrypted = decrypt(message, nonce, key)
    len_msg   = len(decrypted)
    message   = decrypted[:len_msg-2]
    msg_crc   = decrypted[len_msg-2:len_msg]
    msg_crc   = utils.u16_unpack(msg_crc)
    crc_val   = utils.get_crc(message)
    auth_id   = message[0:4]
    auth_id   = utils.u32_unpack(auth_id)
    message   = message[4:]
    
    if( msg_crc != crc_val ):
        print "crc error: " + str(hex(crc_val))
        
    utils.verify_crc(decrypted)

    return auth_id, message, decrypted

def decrypt(message, nonce, key):        
    box       = nacl.secret.SecretBox(key)
    decrypted = box.decrypt(message, nonce)
    return decrypted

def pdata(cmd_id, message):
    message = cmd_id + message   
    message = utils.add_crc(message)     
    return message

def get_pdata(pdata):
    len_msg = len(pdata)
    message = pdata[:len_msg-2]
    msg_crc = pdata[len_msg-2:len_msg]
    msg_crc = utils.u16_unpack(msg_crc)
    crc_val = utils.get_crc(message)
    cmd_id  = message[:2]
    message = message[2:]
    
    if( msg_crc != crc_val ):
        print "crc error: " + hexlify(crc_val)

    return cmd_id, message

def get_auth_id(message):
    auth_id = message[24:28]
    return utils.u32_unpack(auth_id)
