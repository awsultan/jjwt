/*
 * Copyright (C) 2020 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.Jwts
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.AeadAlgorithm
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals

/**
 * @since 0.12.0
 */
class HmacAesAeadAlgorithmTest {

    @Test
    void testKeyBitLength() {
        // asserts that key lengths are double than what is usually expected for AES
        // due to the encrypt-then-mac scheme requiring two separate keys
        // (encrypt key is half of the generated key, mac key is the 2nd half of the generated key):
        assertEquals 256, Jwts.ENC.A128CBC_HS256.getKeyBitLength()
        assertEquals 384, Jwts.ENC.A192CBC_HS384.getKeyBitLength()
        assertEquals 512, Jwts.ENC.A256CBC_HS512.getKeyBitLength()
    }

    @Test
    void testGenerateKey() {
        def algs = [
                Jwts.ENC.A128CBC_HS256,
                Jwts.ENC.A192CBC_HS384,
                Jwts.ENC.A256CBC_HS512
        ]
        for (AeadAlgorithm alg : algs) {
            SecretKey key = alg.key().build()
            assertEquals alg.getKeyBitLength(), Bytes.bitLength(key.getEncoded())
        }
    }

    @Test(expected = SignatureException)
    void testDecryptWithInvalidTag() {

        def alg = Jwts.ENC.A128CBC_HS256

        SecretKey key = alg.key().build()

        byte[] data = Strings.utf8('Hello World! Nice to meet you!')
        def plaintext = Streams.of(data)

        ByteArrayOutputStream out = new ByteArrayOutputStream(8192)
        def res = new DefaultAeadResult(out)
        def req = new DefaultAeadRequest(plaintext, null, null, key, null)

        alg.encrypt(req, res)

        def iv = res.getIv()
        def realTag = res.getDigest()

        //fake it:
        def fakeTag = new byte[realTag.length]
        Randoms.secureRandom().nextBytes(fakeTag)

        byte[] ciphertext = out.toByteArray()
        out = new ByteArrayOutputStream(8192)
        def dreq = new DefaultDecryptAeadRequest(Streams.of(ciphertext), key, null, iv, fakeTag)
        alg.decrypt(dreq, out)
    }
}
