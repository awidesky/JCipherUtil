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
 * Optional data is {@code KeyMetadata} and buffer value. These values are each default initialized to {@code KeyMetadata#DEFAULT}
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
	 * Initialize the builder with given key size.
	 * */
	public SymmetricCipherUtilBuilder(KeySize keySize) {
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
	 * Configure buffer value. original default value is 8KB.
	 * This is optional operation.
	 * */
	public SymmetricCipherUtilBuilder<T> bufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
		return this;
	}
	/**
	 * Configure key size. original default value is given at the constructor.
	 * This is optional operation.
	 * */
	public SymmetricCipherUtilBuilder<T> keySize(KeySize keySize) {
		this.keySize = keySize;
		return this;
	}
	
	
	protected abstract T generate();

	/**
	 * Returns a new {@code CipherUtil} instance configured with specified parameters and given password.
	 * 
	 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
	 * @param password password for the secret key
	 * */
	public T build(char[] password) {
		keyMet = new PasswordKeyMaterial(password);
		return generate();
	}
	/**
	 * Returns a new {@code CipherUtil} instance configured with specified parameters and given <code>byte[]</code> key.
	 * 
	 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
	 * @param key the secret key data which used as <code>SecretKey</code>(after key stretching)
	 * */
	public T build(byte[] key) {
		keyMet = new ByteArrayKeyMaterial(key);
		return generate();
	}
}
