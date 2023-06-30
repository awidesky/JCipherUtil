/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.symmetric.aes;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricNonceCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.properties.IVCipherProperty;

public class AES_CBCCipherUtil extends SymmetricNonceCipherUtil {

	public final static IVCipherProperty METADATA = new IVCipherProperty("AES", "CBC", "PKCS5PADDING", "AES", 16);
	
	public AES_CBCCipherUtil(SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(METADATA, keyMetadata, bufferSize);
	}
	

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected IVCipherProperty getCipherProperty() { return METADATA; }

}
