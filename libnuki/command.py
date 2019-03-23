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

from binascii import hexlify, a2b_hex

import nacl.bindings
import nuki_utils as utils


def get_cmd_id(message):
    cmd_id = message[0:2]
    cmd_id = utils.u16_unpack(cmd_id)
    return cmd_id

def request_data(additional_data):
    cmd_id  = 0x0001
    cmd_id  = utils.pack_u16(cmd_id)
    message = cmd_id + additional_data
    return message

def public_key_request():
    cmd_id  = 0x0003
    cmd_id  = utils.pack_u16(cmd_id)
    message = request_data(cmd_id)
    return message

def public_key(key):
    cmd_id  = 0x0003
    cmd_id  = utils.pack_u16(cmd_id)
    message = cmd_id + key
    return message

def public_key_decode(message):
    #cmd_id = 0x0003
    p_key   = message[2:34]
    return p_key

def challenge_request(auth_id, key):
    cmd_id  = 0x0004
    cmd_id  = utils.pack_u16(cmd_id)
    message = request_data(cmd_id)
    return message

def challenge_decode(message):
    #cmd_id = 0x0004
    return message[2:34]

def authenticator(public_key_bridge, public_key_sl, challenge, key):
    cmd_id  = 0x0005
    cmd_id  = utils.pack_u16(cmd_id)
    r       = public_key_bridge + public_key_sl + challenge
    auth_h  = nacl.bindings.crypto_auth_hmacsha256(r, key)
    message = cmd_id + auth_h
    return message

def authorization_data(id_type, bridge_id, name, nonce_abf, nonce_k, key):
    cmd_id    = 0x0006
    cmd_id    = utils.pack_u16(cmd_id)        
    id_type   = utils.pack_u8(id_type)
    bridge_id = utils.pack_u32(bridge_id)
    z_fill    = a2b_hex('0000000000000000000000000000000000000000000000000000000000000000')
    name      = a2b_hex(hexlify(name))[:15] + z_fill
    name      = name[:32]
    message   = id_type + bridge_id + name + nonce_abf + nonce_k
    auth_h    = nacl.bindings.crypto_auth_hmacsha256(message, key)
    message   = cmd_id + auth_h + id_type + bridge_id + name + nonce_abf
    return message

def authorization_id_decode(message):
    #cmd_id = 0x0007
    auth_id = message[34:38]
    auth_id = utils.u32_unpack(auth_id)
    uuid    = message[38:54]
    nonce_k = message[54:86]
    return auth_id, uuid, nonce_k

def nuki_states_request():
    cmd_id  = 0x000C
    cmd_id  = utils.pack_u16(cmd_id)
    message = request_data(cmd_id)
    return message

def nuki_states_decode(message):
    #cmd_id = 0x000C
    n_stat  = message[2:3]
    l_stat  = message[3:4]
    trigger = message[4:5]
    time    = message[5:12]
    time_z  = message[12:14]
    bat     = message[14:15]
    n_stat  = utils.u8_unpack(n_stat)
    l_stat  = utils.u8_unpack(l_stat)
    trigger = utils.u8_unpack(trigger)
    time    = utils.decode_time(time)
    time_z  = utils.s16_unpack(time_z)
    bat     = utils.u8_unpack(bat)
    return n_stat, l_stat, trigger, time, time_z, bat

def lock_action(auth_id, lock_action, bridge_id, flags, nonce_k):
    cmd_id      = 0x000D
    cmd_id      = utils.pack_u16(cmd_id)
    lock_action = utils.pack_u8(lock_action)
    bridge_id   = utils.pack_u32(bridge_id)
    flags       = utils.pack_u8(flags)
    message     = cmd_id + lock_action + bridge_id + flags + nonce_k
    return message

def status_decode(message):
    #cmd_id = 0x000E
    status  = message[2:3]
    status  = utils.u8_unpack(status)
    return status

def battery_report_request():
    cmd_id    = 0x0011
    cmd_id    = utils.pack_u16(cmd_id)
    message   = request_data(cmd_id)
    return message

def battery_report_decode(message):
    #cmd_id     = 0x0011
    bat_drain   = message[2:4]
    bat_voltage = message[4:6]
    bat_state   = message[6:7]
    bat_drain   = utils.u16_unpack(bat_drain)
    bat_voltage = utils.u16_unpack(bat_voltage)
    bat_state   = utils.u8_unpack(bat_state)
    return bat_drain, bat_voltage, bat_state

def error_report(error_code, command):
    cmd_id     = 0x0012
    cmd_id     = utils.pack_u16(cmd_id)
    error_code = utils.pack_u8(error_code)
    command    = utils.pack_u16(command)
    message    = cmd_id + error_code + command
    return message

def error_report_decode(message):
    #cmd_id    = 0x0012
    error_code = message[2:3]
    command    = message[3:5]
    error_code = utils.u8_unpack(error_code)
    command    = utils.u16_unpack(command)
    return error_code, command

def config_request_encode():
    cmd_id     = 0x0014
    cmd_id     = utils.pack_u16(cmd_id)
    message = cmd_id
    return message

def config_decode(message):
    #cmd_id     = 0x0011
    sl_config = {}
    return sl_config

def authorization_id_confirmation(auth_id, nonce_abf, key):
    cmd_id  = 0x001E
    cmd_id  = utils.pack_u16(cmd_id)
    auth_id = utils.pack_u32(auth_id)
    message  = auth_id + nonce_abf
    auth_h   = nacl.bindings.crypto_auth_hmacsha256(message, key)
    message  = cmd_id + auth_h + auth_id
    return message

def update_time(time, nonce_k, sec_pin):
    cmd_id  = 0x0021
    cmd_id  = utils.pack_u16(cmd_id)
    sec_pin = utils.pack_u16(sec_pin)
    message = cmd_id + time + nonce_k + sec_pin
    return message

def error_bridge(error_code, command):
    cmd_id     = 0x8012
    cmd_id     = utils.pack_u16(cmd_id)
    error_code = utils.pack_u8(error_code)
    command    = utils.pack_u16(command)
    message    = cmd_id + error_code + command
    return message

def error_bridge_decode(message):
    #cmd_id    = 0x8012
    error_code = message[2:3]
    command    = message[3:5]
    error_code = utils.u8_unpack(error_code)
    command    = utils.u16_unpack(command)
    return error_code, command
