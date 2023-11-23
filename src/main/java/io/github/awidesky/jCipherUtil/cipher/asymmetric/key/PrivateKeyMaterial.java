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
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import io.github.awidesky.jCipherUtil.exceptions.NotSupposedToThrownException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;

public class PrivateKeyMaterial extends AsymmetricKeyMaterial {

	private final byte[] pkcs8EncodedPrivateKey;
	
	public PrivateKeyMaterial(PrivateKey privateKey) {
		this(privateKey.getEncoded());
	}
	public PrivateKeyMaterial(byte[] privateKey) {
		pkcs8EncodedPrivateKey = Arrays.copyOf(privateKey, privateKey.length);
	}
	public PrivateKeyMaterial(String privateKey) {
		pkcs8EncodedPrivateKey = Base64.getDecoder().decode(privateKey);
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
			return new KeyPair(null, KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedPrivateKey)));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new NotSupposedToThrownException(e);
		}
	}

	/**
	 * Returns a copy of pkcs8 encoded private key.
	 * @return a copy of pkcs8 encoded private key.
	 */
	public byte[] getEncoded() {
		return Arrays.copyOf(pkcs8EncodedPrivateKey, pkcs8EncodedPrivateKey.length);
	}
	@Override
	public void destroy() {
		clearArray(pkcs8EncodedPrivateKey);
		destroyed = true;
	}
}
