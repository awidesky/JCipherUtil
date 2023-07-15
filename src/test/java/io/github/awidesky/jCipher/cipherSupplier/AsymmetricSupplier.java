/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipherSupplier;

import io.github.awidesky.jCipher.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipher.key.KeySize;

public abstract class AsymmetricSupplier {

	protected final KeySize keySize;
	protected final int bufferSize;
	
	public AsymmetricSupplier(KeySize keySize, int bufferSize) {
		this.keySize = keySize;
		this.bufferSize = bufferSize;
	}
	
	public abstract AsymmetricCipherUtil withPublicOnly();
	public abstract AsymmetricCipherUtil withPrivateOnly();
	public abstract AsymmetricCipherUtil withBothKey();
}
