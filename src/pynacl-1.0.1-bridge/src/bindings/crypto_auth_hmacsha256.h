/* Copyright 2016 Fivebanger
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


size_t crypto_auth_hmacsha256_bytes();

                       
int crypto_auth_hmacsha256(unsigned char *out, const unsigned char *in,
                           unsigned long long inlen, const unsigned char *k);

int crypto_auth_hmacsha256_verify(const unsigned char *h, const unsigned char *in,
                                  unsigned long long inlen, const unsigned char *k);
