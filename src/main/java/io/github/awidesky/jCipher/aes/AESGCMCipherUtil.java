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

import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.KeyMetadata;

public class AESGCMCipherUtil extends AbstractAESCipherUtil {

	public final static CipherProperty METADATA = new CipherProperty("AES", "GCM", "NoPadding", "AES", 12);
	public final static int GCM_TAG_BIT_LENGTH = 128;
	
	public AESGCMCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected CipherProperty getCipherMetadata() { return METADATA; }


	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new GCMParameterSpec(GCM_TAG_BIT_LENGTH, IV);
	}

}
