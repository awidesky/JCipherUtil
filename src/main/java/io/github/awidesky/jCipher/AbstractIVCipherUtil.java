/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.IVCipherProperty;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AbstractIVCipherUtil extends AbstractCipherUtil {

	protected byte[] IV;
	
	protected AbstractIVCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) { super(cipherMetadata, keyMetadata, bufferSize); }

	protected abstract AlgorithmParameterSpec getAlgorithmParameterSpec();
	
	/**
	 * Generate random IV with given {@code SecureRandom} instance.
	 * Size of the IV is determined by {@code CipherProperty}.
	 * 
	 * @see CipherProperty#NONCESIZE
	 * */
	protected void generateIV(SecureRandom sr) {
		IV = new byte[getCipherProperty().NONCESIZE];
		sr.nextBytes(IV);
	}
	/**
	 * Read IV from given {@code MessageProvider} instance.
	 * Size of the IV is determined by {@code CipherProperty}.
	 * 
	 * @see CipherProperty#NONCESIZE
	 * */
	protected void readIV(MessageProvider mp) {
		IV = new byte[getCipherProperty().NONCESIZE];
		int read = 0;
		while ((read += mp.getSrc(IV, read)) != IV.length);
	}
	
	@Override
	protected abstract IVCipherProperty getCipherProperty();

	@Override
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		generateSalt(sr);
		generateIterationCount(sr);
		generateIV(sr);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		mc.consumeResult(IV);
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		readIterationCount(mp);
		readSalt(mp);
		readIV(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	protected String fields() {
		return super.fields() + ", Nonce Size : " + getCipherProperty().NONCESIZE + "byte";
	}

}
