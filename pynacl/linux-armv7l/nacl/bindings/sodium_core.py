# Copyright 2013 Donald Stufft and individual contributors
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
from __future__ import absolute_import, division, print_function

from nacl._sodium import ffi, lib
from nacl.exceptions import CryptoError


crypto_core_hsalsa20_output_BYTES = lib.crypto_core_hsalsa20_outputbytes()


def sodium_init():
    """
    Initializes sodium, picking the best implementations available for this
    machine.
    """
    if lib.sodium_init() != 0:
        raise CryptoError("Could not initialize sodium")


def crypto_core_hsalsa20(message, k, sigma):
    """
    :param message: bytes
    :rtype: bytes
    """
    q = ffi.new("unsigned char[]", crypto_core_hsalsa20_output_BYTES)
    rc = lib.crypto_core_hsalsa20(q, message, k, sigma)
    assert rc == 0
    return ffi.buffer(q, crypto_core_hsalsa20_output_BYTES)[:]
