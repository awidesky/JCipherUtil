/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.asymmetric;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.KeyPairMaterial;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.PrivateKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.PublicKeyMaterial;

/**
 * Builder for {@code AsymmetricCipherUtil}.
 * */
public abstract class AsymmetricCipherUtilBuilder <T extends AsymmetricCipherUtil> {

	protected AsymmetricKeyMaterial keyMet;
	protected int bufferSize = 8 * 1024;
	
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code PublicKey}.
	 * */
	public AsymmetricCipherUtilBuilder(PublicKey key) {
		keyMet = new PublicKeyMaterial(key);
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with {@code PrivateKey} only.
	 * */
	public AsymmetricCipherUtilBuilder(PrivateKey key) {
		keyMet = new PrivateKeyMaterial(key);
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with {@code KeyPair} only.
	 * */
	public AsymmetricCipherUtilBuilder(KeyPair keyPair) {
		keyMet = new KeyPairMaterial(keyPair);
	}
	
	/**
	 * Determine buffer size. Default is 8KB.
	 * <p>This method is optional operation. 
	 * */
	public AsymmetricCipherUtilBuilder<T> bufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
		return this;
	}
	
	/**
	 * Returns generated {@code AsymmetricCipherUtil}.
	 * */
	public abstract T build();
}
