/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.asymmetric.key;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public class PublicKeyOnlyKeyMaterial extends AsymmetricKeyMaterial {

	private final byte[] x509EncodedPublicKey;
	
	public PublicKeyOnlyKeyMaterial(PublicKey publicKey) {
		this(publicKey.getEncoded());
	}
	public PublicKeyOnlyKeyMaterial(byte[] publicKey) {
		x509EncodedPublicKey = Arrays.copyOf(publicKey, publicKey.length);
	}
	public PublicKeyOnlyKeyMaterial(String publicKey) {
		x509EncodedPublicKey = Base64.getDecoder().decode(publicKey);
	}
	
	@Override
	public KeyPair getKey(String algorithm) {
		try {
			return new KeyPair(KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey)), null);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}

}
