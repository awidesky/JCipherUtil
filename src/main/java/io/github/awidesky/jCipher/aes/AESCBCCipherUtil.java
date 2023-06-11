/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.aes;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipher.metadata.CipherProperty;

public class AESCBCCipherUtil extends AbstractAESCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16, 256);
	
	public AESCBCCipherUtil(int bufferSize) {
		super(METADATA, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected CipherProperty getCipherMetadata() { return METADATA; }


	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new IvParameterSpec(IV);
	}


}
