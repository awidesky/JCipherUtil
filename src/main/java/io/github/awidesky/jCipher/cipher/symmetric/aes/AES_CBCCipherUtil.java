/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.symmetric.aes;

import io.github.awidesky.jCipher.AbstractIVCipherUtil;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

public class AES_CBCCipherUtil extends AbstractIVCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16);
	
	public AES_CBCCipherUtil(KeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
