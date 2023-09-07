/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * An AES/CBC/PKCS5PADDING {@code CipherUtil} with 16 byte IV.
 * */
public class AES_CBCCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16);
	
	/**
	 * Construct this {@code AES_CBCCipherUtil} with given parameters.
	 * */
	private AES_CBCCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}
	
	/**
	 * @return <code>CipherProperty</code> of this <code>AES_CBCCipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder<AES_CBCCipherUtil> {
		
		/**
		 * Specify binary private key data and AES key value.
		 * <p>The private key data is <b>not</b> directly used as an AES key. Instead it will salted and hashed
		 * multiple times.
		 * 
		 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
		 * */
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		/**
		 * Specify password and AES key value.
		 * 
		 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
		 * */
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		/**
		 * Returns generated {@code AES_CBCCipherUtil}.
		 * */
		@Override
		public AES_CBCCipherUtil build() { return new AES_CBCCipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}

}
