/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipherSupplier;

import java.security.KeyPair;

import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa.RSAKeySize;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa.RSA_ECBCipherUtil;

public class RSA_ECBSupplier extends AsymmetricSupplier {

	private final KeyPair key;
	
	public RSA_ECBSupplier(RSAKeySize keySize, int bufferSize) {
		super(keySize, bufferSize);
		key = RSA_ECBCipherUtil.generateKeyPair(keySize);
	}

	@Override
	public AsymmetricCipherUtil withPublicOnly() {
		return new RSA_ECBCipherUtil.Builder(key.getPublic()).bufferSize(bufferSize).build();
	}

	@Override
	public AsymmetricCipherUtil withPrivateOnly() {
		return new RSA_ECBCipherUtil.Builder(key.getPrivate()).bufferSize(bufferSize).build();
	}

	@Override
	public AsymmetricCipherUtil withBothKey() {
		return new RSA_ECBCipherUtil.Builder(key).bufferSize(bufferSize).build();
	}

}
