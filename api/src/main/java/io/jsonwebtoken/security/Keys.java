/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Utility class for securely generating {@link SecretKey}s and {@link KeyPair}s.
 *
 * @since 0.10.0
 */
public final class Keys {

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeysBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] FOR_PASSWORD_ARG_TYPES = new Class[]{char[].class};
    private static final Class<?>[] SECRET_BUILDER_ARG_TYPES = new Class[]{SecretKey.class};
    private static final Class<?>[] PRIVATE_BUILDER_ARG_TYPES = new Class[]{PrivateKey.class};

    private static <T> T invokeStatic(String method, Class<?>[] argTypes, Object... args) {
        return Classes.invokeStatic(BRIDGE_CLASS, method, argTypes, args);
    }

    //prevent instantiation
    private Keys() {
    }

    /**
     * Creates a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
     *
     * @param bytes the key byte array
     * @return a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
     * @throws WeakKeyException if the key byte array length is less than 256 bits (32 bytes) as mandated by the
     *                          <a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWT JWA Specification
     *                          (RFC 7518, Section 3.2)</a>
     */
    public static SecretKey hmacShaKeyFor(byte[] bytes) throws WeakKeyException {

        if (bytes == null) {
            throw new InvalidKeyException("SecretKey byte array cannot be null.");
        }

        int bitLength = bytes.length * 8;

        //Purposefully ordered higher to lower to ensure the strongest key possible can be generated.
        if (bitLength >= 512) {
            return new SecretKeySpec(bytes, "HmacSHA512");
        } else if (bitLength >= 384) {
            return new SecretKeySpec(bytes, "HmacSHA384");
        } else if (bitLength >= 256) {
            return new SecretKeySpec(bytes, "HmacSHA256");
        }

        String msg = "The specified key byte array is " + bitLength + " bits which " +
                "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " +
                "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " +
                "size >= 256 bits (the key size must be greater than or equal to the hash " +
                "output size).  Consider using the Jwts.SIG.HS256.key() builder (or HS384.key() " +
                "or HS512.key()) to create a key guaranteed to be secure enough for your preferred HMAC-SHA " +
                "algorithm.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
        throw new WeakKeyException(msg);
    }

    /**
     * Returns a new {@link Password} instance suitable for use with password-based key derivation algorithms.
     *
     * <p><b>Usage Note</b>: Using {@code Password}s outside of key derivation contexts will likely
     * fail. See the {@link Password} JavaDoc for more, and also note the <b>Password Safety</b> section below.</p>
     *
     * <p><b>Password Safety</b></p>
     *
     * <p>Instances returned by this method use a <em>clone</em> of the specified {@code password} character array
     * argument - changes to the argument array will NOT be reflected in the returned key, and vice versa.  If you wish
     * to clear a {@code Password} instance to ensure it is no longer usable, call its {@link Password#destroy()}
     * method will clear/overwrite its internal cloned char array. Also note that each subsequent call to
     * {@link Password#toCharArray()} will also return a new clone of the underlying password character array per
     * standard JCE key behavior.</p>
     *
     * @param password the raw password character array to clone for use with password-based key derivation algorithms.
     * @return a new {@link Password} instance that wraps a new clone of the specified {@code password} character array.
     * @see Password#toCharArray()
     * @since 0.12.0
     */
    public static Password password(char[] password) {
        return invokeStatic("password", FOR_PASSWORD_ARG_TYPES, new Object[]{password});
    }

    /**
     * Returns a {@code SecretKeyBuilder} that produces the specified key, allowing association with a
     * {@link SecretKeyBuilder#provider(Provider) provider} that must be used with the key during cryptographic
     * operations.  For example:
     *
     * <blockquote><pre>
     * SecretKey key = Keys.builder(key).provider(mandatoryProvider).build();</pre></blockquote>
     *
     * <p>Cryptographic algorithm implementations can inspect the resulting {@code key} instance and obtain its
     * mandatory {@code Provider} if necessary.</p>
     *
     * <p>This method is primarily only useful for keys that cannot expose key material, such as PKCS11 or HSM
     * (Hardware Security Module) keys, and require a specific {@code Provider} to be used during cryptographic
     * operations.</p>
     *
     * @param key the secret key to use for cryptographic operations, potentially associated with a configured
     *            {@link Provider}
     * @return a new {@code SecretKeyBuilder} that produces the specified key, potentially associated with any
     * specified provider.
     * @since 0.12.0
     */
    public static SecretKeyBuilder builder(SecretKey key) {
        Assert.notNull(key, "SecretKey cannot be null.");
        return invokeStatic("builder", SECRET_BUILDER_ARG_TYPES, key);
    }

    /**
     * Returns a {@code PrivateKeyBuilder} that produces the specified key, allowing association with a
     * {@link PrivateKeyBuilder#publicKey(PublicKey) publicKey} to obtain public key data if necessary, or a
     * {@link SecretKeyBuilder#provider(Provider) provider} that must be used with the key during cryptographic
     * operations.  For example:
     *
     * <blockquote><pre>
     * PrivateKey key = Keys.builder(privateKey).publicKey(publicKey).provider(mandatoryProvider).build();</pre></blockquote>
     *
     * <p>Cryptographic algorithm implementations can inspect the resulting {@code key} instance and obtain its
     * mandatory {@code Provider} or {@code PublicKey} if necessary.</p>
     *
     * <p>This method is primarily only useful for keys that cannot expose key material, such as PKCS11 or HSM
     * (Hardware Security Module) keys, and require a specific {@code Provider} or public key data to be used
     * during cryptographic operations.</p>
     *
     * @param key the private key to use for cryptographic operations, potentially associated with a configured
     *            {@link Provider} or {@link PublicKey}.
     * @return a new {@code PrivateKeyBuilder} that produces the specified private key, potentially associated with any
     * specified provider or {@code PublicKey}
     * @since 0.12.0
     */
    public static PrivateKeyBuilder builder(PrivateKey key) {
        Assert.notNull(key, "PrivateKey cannot be null.");
        return invokeStatic("builder", PRIVATE_BUILDER_ARG_TYPES, key);
    }
}
