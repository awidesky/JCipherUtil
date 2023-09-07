/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.symmetric.aes;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * An AES/GCM/NoPadding {@code CipherUtil} with 12 byte nonce and 128 bit tag length.
 * */
public class AES_GCMCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "GCM", "NoPadding", "AES", 12);
	public final static int GCM_TAG_BIT_LENGTH = 128;
	
	/**
	 * Construct this {@code AES_GCMCipherUtil} with given parameters.
	 * */
	private AES_GCMCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(keyMetadata, keySize, key, bufferSize);
	}

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec(byte[] nonce) {
		return new GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce);
	}


	public static class Builder extends SymmetricCipherUtilBuilder<AES_GCMCipherUtil> {
		
		/**
		 * Specify binary private key data and AES key size.
		 * <p>The private key data is <b>not</b> directly used as an AES key. Instead it will salted and hashed
		 * multiple times.
		 * 
		 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
		 * */
		public Builder(byte[] key, AESKeySize keySize) { super(key, keySize); }
		/**
		 * Specify password and AES key size.
		 * 
		 * @see PasswordKeyMaterial#PasswordKeyMaterial(char[])
		 * */
		public Builder(char[] password, AESKeySize keySize) { super(password, keySize); }
		
		/**
		 * Returns generated {@code AES_GCMCipherUtil}.
		 * */
		@Override
		public AES_GCMCipherUtil build() { return new AES_GCMCipherUtil(keyMetadata, keySize, keyMet, bufferSize); }
		
	}
}
