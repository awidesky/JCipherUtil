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
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AbstractCipherUtilWithNonce extends AbstractCipherUtil {

	protected byte[] IV;
	
	protected AbstractCipherUtilWithNonce(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) { super(cipherMetadata, keyMetadata, bufferSize); }

	protected abstract AlgorithmParameterSpec getAlgorithmParameterSpec();
	
	@Override
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		IV = new byte[getCipherMetadata().NONCESIZE];
		generateSalt(sr);
		generateIterationCount(sr);
		sr.nextBytes(IV);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		mc.consumeResult(IV);
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		IV = new byte[getCipherMetadata().NONCESIZE];
		readIterationCount(mp);
		readSalt(mp);
		
		int read = 0;
		while ((read += mp.getSrc(IV, read)) != IV.length);
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}

}
