/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.asymmetric;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.awidesky.jCipher.cipher.asymmetric.key.AsymmetricKeyMaterial;
import io.github.awidesky.jCipher.cipher.asymmetric.key.KeyPairKeyMaterial;
import io.github.awidesky.jCipher.cipher.asymmetric.key.PrivateKeyOnlyKeyMaterial;
import io.github.awidesky.jCipher.cipher.asymmetric.key.PublicKeyOnlyKeyMaterial;

public abstract class AsymmetricCipherUtilBuilder <T extends AsymmetricCipherUtil> {

	protected AsymmetricKeyMaterial keyMet;
	protected int bufferSize = 8 * 1024;
	
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code PublicKey}.
	 * */
	public AsymmetricCipherUtilBuilder(PublicKey key) {
		keyMet = new PublicKeyOnlyKeyMaterial(key);
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code PrivateKey}.
	 * */
	public AsymmetricCipherUtilBuilder(PrivateKey key) {
		keyMet = new PrivateKeyOnlyKeyMaterial(key);
	}
	/**
	 * Initialize this {@code AsymmetricCipherUtil} with given {@code KeyPair}.
	 * */
	public AsymmetricCipherUtilBuilder(KeyPair keyPair) {
		keyMet = new KeyPairKeyMaterial(keyPair);
	}
	

	public AsymmetricCipherUtilBuilder<T> bufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
		return this;
	}
	
	
	/**
	 * */
	public abstract T build();
}
