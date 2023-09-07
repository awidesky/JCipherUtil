/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.symmetric;

import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;

/**
 * A builder class for symmetric cipherUtil.
 * Necessary data are {@code SymmetricKeyMaterial} and {@code KeySize}. These values must be provided to constructor.
 * Optional data is {@code KeyMetadata} and buffer size. These values are each default initialized to {@code KeyMetadata#DEFAULT}
 * and 8KB, but custom value can configured by {@code SymmetricCipherUtilBuilder#keyMetadata(KeyMetadata)} and
 * {@code SymmetricCipherUtilBuilder#bufferSize(int)}
 * @param <T>
 */
public abstract class SymmetricCipherUtilBuilder <T extends SymmetricCipherUtil> {

	protected SymmetricKeyMaterial keyMet;
	protected KeySize keySize;
	protected KeyMetadata keyMetadata = KeyMetadata.DEFAULT;
	protected int bufferSize = 8 * 1024;
	
	/**
	 * Initialize <code>AsymmetricCipherUtilBuilder</code> with given password and key size.
	 * 
	 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
	 * */
	public SymmetricCipherUtilBuilder(char[] password, KeySize keySize) {
		keyMet = new PasswordKeyMaterial(password);
		this.keySize = keySize;
	}
	/**
	 * Initialize <code>AsymmetricCipherUtilBuilder</code> with given <code>byte[]</code> key and key size.
	 * <p><i><b>The argument byte array is directly used as <code>SecretKey</code>(after key stretching)</b></i>
	 * 
	 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
	 * */
	public SymmetricCipherUtilBuilder(byte[] key, KeySize keySize) {
		keyMet = new ByteArrayKeyMaterial(key);;
		this.keySize = keySize;
	}
	
	/**
	 * Configure {@code KeyMetadata}. original default value is {@code KeyMetadata#DEFAULT}.
	 * This is optional operation.
	 * */
	public SymmetricCipherUtilBuilder<T> keyMetadata(KeyMetadata keyMetadata) {
		this.keyMetadata = keyMetadata;
		return this;
	}
	/**
	 * Configure buffer size. original default value is 8KB.
	 * This is optional operation.
	 * */
	public SymmetricCipherUtilBuilder<T> bufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
		return this;
	}
	
	
	/**
	 * Builds and returns a new {@code SymmetricCipherUtil} configured with specified parameters.
	 * */
	public abstract T build();
}
