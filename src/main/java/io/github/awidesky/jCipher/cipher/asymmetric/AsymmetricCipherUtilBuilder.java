/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.asymmetric;

import io.github.awidesky.jCipher.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;

public abstract class AsymmetricCipherUtilBuilder {

	protected SymmetricKeyMaterial keyMet;
	protected KeySize keySize;
	protected SymmetricKeyMetadata keyMetadata = SymmetricKeyMetadata.DEFAULT;
	protected int bufferSize = 8 * 1024;
	
	/**
	 * Initialize <code>AsymmetricCipherUtilBuilder</code> with given password and key size.
	 * 
	 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
	 * */
	public AsymmetricCipherUtilBuilder(char[] password, KeySize keySize) {
		keyMet = new PasswordKeyMaterial(password);
		this.keySize = keySize;
	}
	/**
	 * Initialize <code>AsymmetricCipherUtilBuilder</code> with given <code>byte[]</code> key and key size.
	 * <p><i><b>The argument byte array is directly used as <code>SecretKey</code>(after key stretching)</b></i>
	 * 
	 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
	 * */
	public AsymmetricCipherUtilBuilder(byte[] key, KeySize keySize) {
		keyMet = new ByteArrayKeyMaterial(key);;
		this.keySize = keySize;
	}
	
	public AsymmetricCipherUtilBuilder keyMetadata(SymmetricKeyMetadata keyMetadata) {
		this.keyMetadata = keyMetadata;
		return this;
	}
	
	public AsymmetricCipherUtilBuilder bufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
		return this;
	}
	
	
	/**
	 * */
	protected abstract AsymmetricCipherUtil getCipherUtil();
}
