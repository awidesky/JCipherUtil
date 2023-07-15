/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.asymmetric.key;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import io.github.awidesky.jCipher.util.OmittedCipherException;

public class PrivateKeyOnlyKeyMaterial extends AsymmetricKeyMaterial {

	private final byte[] pkcs8EncodedprivateKey;
	
	public PrivateKeyOnlyKeyMaterial(PrivateKey privateKey) {
		this(privateKey.getEncoded());
	}
	public PrivateKeyOnlyKeyMaterial(byte[] privateKey) {
		pkcs8EncodedprivateKey = Arrays.copyOf(privateKey, privateKey.length);
	}
	public PrivateKeyOnlyKeyMaterial(String privateKey) {
		pkcs8EncodedprivateKey = Base64.getDecoder().decode(privateKey);
	}
	
	@Override
	public KeyPair getKey(String algorithm) {
		try {
			return new KeyPair(null, KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedprivateKey)));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}

}
