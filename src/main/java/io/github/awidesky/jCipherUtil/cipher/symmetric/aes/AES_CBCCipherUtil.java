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
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
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
		 * Initialize the builder with given key size.
		 * */
		public Builder(AESKeySize keySize) {
			super(keySize);
		}
		
		/**
		 * Returns generated {@code AES_CBCCipherUtil}.
		 * */
		@Override
		public AES_CBCCipherUtil generate() { return new AES_CBCCipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}

}
