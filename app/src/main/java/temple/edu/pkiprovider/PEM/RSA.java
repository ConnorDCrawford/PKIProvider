/**
 * Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */

package temple.edu.pkiprovider.PEM;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility for RSA keys.
 */
final class RSA {

    /** String identifying key type. */
    private static final String RSA = "RSA";

    /** Utility class. */
    private RSA() {
    }

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8
     * format.
     *
     * @param pkcs8 byte array containing key data.
     * @return private key parsed from key data.
     * @throws InvalidKeySpecException if PKCS#8 key spec unavailable.
     */
    public static PrivateKey privateKeyFromPKCS8(byte[] pkcs8) throws InvalidKeySpecException
    {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a public key constructed from the given DER bytes in X509
     * format.
     *
     * @param x509 byte array containing key data.
     * @return public key parsed from key data.
     * @throws InvalidKeySpecException if X509 key spec unavailable.
     */
    public static PublicKey publicKeyFromX509(byte[] x509) throws InvalidKeySpecException
    {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}