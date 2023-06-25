/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.symmetric.aes;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipher.AbstractIVCipherUtil;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AES_GCMCipherUtil extends AbstractIVCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "GCM", "NoPadding", "AES", 12);
	public final static int GCM_TAG_BIT_LENGTH = 128;
	
	public AES_GCMCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }


	@Override
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new GCMParameterSpec(GCM_TAG_BIT_LENGTH, IV);
	}

}
