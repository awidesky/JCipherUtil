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

import io.github.awidesky.jCipher.AbstractIVCipherUtil;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AESCBCCipherUtil extends AbstractIVCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16);
	
	public AESCBCCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new IvParameterSpec(IV);
	}


}
