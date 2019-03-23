# Copyright 2016 Fivebanger and individual contributors
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


crypto_auth_hmacsha256_BYTES = lib.crypto_auth_hmacsha256_bytes()


def crypto_auth_hmacsha256(message, k):
    """
    :param message: bytes
    :param k:       bytes
    :rtype: bytes
    """
    q = ffi.new("unsigned char[]", crypto_auth_hmacsha256_BYTES)
    rc = lib.crypto_auth_hmacsha256(q, message, len(message), k)
    assert rc == 0
    return ffi.buffer(q, crypto_auth_hmacsha256_BYTES)[:]

    
def crypto_auth_hmacsha256_verify(h, message, k):
    """
    :param h:       bytes
    :param message: bytes
    :param k:       bytes
    :rtype: bytes
    """
    rc = lib.crypto_auth_hmacsha256_verify(h, message, len(message), k)
    return rc
    