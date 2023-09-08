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

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;

public class PublicKeyMaterial extends AsymmetricKeyMaterial {

	private final byte[] x509EncodedPublicKey;
	
	public PublicKeyMaterial(PublicKey publicKey) {
		this(publicKey.getEncoded());
	}
	public PublicKeyMaterial(byte[] publicKey) {
		x509EncodedPublicKey = Arrays.copyOf(publicKey, publicKey.length);
	}
	public PublicKeyMaterial(String publicKey) {
		x509EncodedPublicKey = Base64.getDecoder().decode(publicKey);
	}
	
	/** 
	 * Return {@code KeyPair} as given {@code algorithm}.
	 * 
	 * @see CipherProperty#KEY_ALGORITMH_NAME
	 * 
	 * @throws OmittedCipherException if {@link NoSuchAlgorithmException} or {@code InvalidKeySpecException} is thrown
	 * @throws IllegalStateException if this object is destroyed
	 * */
	@Override
	public KeyPair getKey(String algorithm) {
		if(destroyed) throw new IllegalStateException("The key material is destroyed!");
		try {
			return new KeyPair(KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(x509EncodedPublicKey)), null);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	@Override
	public void destroy() {
		clearArray(x509EncodedPublicKey);
		destroyed = true;
	}

}
