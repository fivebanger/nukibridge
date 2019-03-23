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

import struct
import datetime
from ctypes import c_ushort


def le2be32(i):
    return (struct.unpack("<I", struct.pack(">I", i))[0])


def le2be16(i):
    return (struct.unpack("<I", struct.pack(">I", i))[0])>>16
  
def u32_unpack(i):
    return (struct.unpack("I", i)[0])
  
def f32_unpack(i):
    return (struct.unpack("f", i)[0])

def u16_unpack(i):
    return (struct.unpack("H", i)[0])

def u8_unpack(i):
    return (struct.unpack("B", i)[0])

def s16_unpack(i):
    return (struct.unpack("h", i)[0]) 
  
def pack_u32(i):
    return (struct.pack("I", i))
  
def pack_f32(i):
    return (struct.pack("f", i))

def pack_u16(i):
    return (struct.pack("H", i))


def pack_u8(i):
    return (struct.pack("B", i)) 

def pack_s16(i):
    return (struct.pack("h", i))    

    
def add_crc(message):
    crc     = CRCCCITT('FFFF')
    crc_val = crc.calculate(message)
    crc_val = struct.pack("H", crc_val)
    return message + crc_val


def get_crc(message):
    crc     = CRCCCITT('FFFF')
    crc_val = crc.calculate(message)
    return crc_val


def verify_crc(message):
    crc     = CRCCCITT('FFFF')
    crc_msg = message[(len(message)-2):len(message)]
    crc_msg = struct.unpack("H", crc_msg)[0]
    msg     = message[0:(len(message)-2)]
    crc_val = crc.calculate(msg)
    retval = 0
    if( crc_msg != crc_val):
        #print 'CRC error'
        retval = -1
    return retval


def get_time():
    current_t = datetime.datetime.now()
    year   = current_t.year
    month  = current_t.month
    day    = current_t.day
    hour   = current_t.hour
    minute = current_t.minute
    sec    = current_t.second
    
    year   = pack_u16(year)
    month  = pack_u8(month)
    day    = pack_u8(day)
    hour   = pack_u8(hour)
    minute = pack_u8(minute)
    sec    = pack_u8(sec)
    
    time = year + month + day + hour + minute + sec
    return time


def decode_time(time):
    year   = time[0:2]
    year   = u16_unpack(year)
    year   = le2be16(year)
    year   = pack_u16(year)
    time = (year + time[2:7])
    return time


class CRCCCITT(object):
    crc_ccitt_table = []
    #original source: https://github.com/cristianav/PyCRC/blob/master/PyCRC/CRCCCITT.py
    
    # The CRC's are computed using polynomials.
    # Here is the most used coefficient for CRC CCITT
    crc_ccitt_constant = 0x1021

    def __init__(self, version='XModem'):
        try:
            dict_versions = {'XModem': 0x0000, 'FFFF': 0xffff, '1D0F': 0x1d0f}
            if version not in dict_versions.keys():
                raise Exception("Your version parameter should be one of \
                    the {} options".format("|".join(dict_versions.keys())))

            self.starting_value = dict_versions[version]

            # initialize the precalculated tables
            if not len(self.crc_ccitt_table):
                self.init_crc_table()
        except Exception as e:
            print("EXCEPTION(__init__): {}".format(e))

    def calculate(self, input_data=None):
        try:
            is_string = isinstance(input_data, str)
            is_bytes = isinstance(input_data, (bytes, bytearray))

            if not is_string and not is_bytes:
                raise Exception("Please provide a string or a byte sequence \
                    as argument for calculation.")

            crc_value = self.starting_value

            for c in input_data:
                d = ord(c) if is_string else c
                tmp = ((crc_value >> 8) & 0xff) ^ d
                crc_value = ((crc_value << 8) & 0xff00) ^ self.crc_ccitt_table[tmp]

            return crc_value
        except Exception as e:
            print("EXCEPTION(calculate): {}".format(e))

    def init_crc_table(self):
        """The algorithm uses tables with precalculated values"""
        for i in range(0, 256):
            crc = 0
            c = i << 8

            for j in range(0, 8):
                if (crc ^ c) & 0x8000:
                    crc = c_ushort(crc << 1).value ^ self.crc_ccitt_constant
                else:
                    crc = c_ushort(crc << 1).value

                c = c_ushort(c << 1).value  # equivalent of c = c << 1

            self.crc_ccitt_table.append(crc)
            
