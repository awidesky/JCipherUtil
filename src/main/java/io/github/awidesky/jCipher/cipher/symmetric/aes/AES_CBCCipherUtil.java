/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.symmetric.aes;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipher.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.properties.IVCipherProperty;

public class AES_CBCCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16);
	
	/**
	 * Construct this {@code AES_CBCCipherUtil} with given parameters.
	 * */
	private AES_CBCCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, keyMetadata, keySize, key, bufferSize);
	}
	
	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	public static class Builder extends SymmetricCipherUtilBuilder {
		
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		@Override
		public AES_CBCCipherUtil build() { return new AES_CBCCipherUtil(METADATA, keyMetadata, keySize, keyMet, bufferSize); }
		
	}

}
