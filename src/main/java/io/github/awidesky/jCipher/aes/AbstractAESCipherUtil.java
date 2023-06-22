/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.aes;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.KeyMetadata;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class AbstractAESCipherUtil extends AbstractCipherUtil {

	protected byte[] IV;
	
	protected AbstractAESCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) { super(cipherMetadata, keyMetadata, bufferSize); }

	protected abstract AlgorithmParameterSpec getAlgorithmParameterSpec();
	
	/**
	 * Return copy of Initial Vector
	 * @Deprecated probably no use, an cause confusion to figure out since returning IV is used in previous cipher task
	 * */
	@Deprecated
	protected byte[] getIV() { return Arrays.copyOf(IV, IV.length); }
	
	@Override
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		IV = new byte[getCipherMetadata().NONCESIZE];
		byte[] salt = new byte[keyMetadata.saltLen]; 
		int iteration;
		
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(IV);
		sr.nextBytes(salt);

		iteration = sr.nextInt(keyMetadata.iterationRange[0], keyMetadata.iterationRange[1]);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iteration), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException  e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iteration).array());
		mc.consumeResult(salt);
		mc.consumeResult(IV);
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		IV = new byte[getCipherMetadata().NONCESIZE];
		byte[] salt = new byte[keyMetadata.saltLen]; 
		int iteration;
		byte[] iterationByte = new byte[4];
		
		int read = 0;
		while ((read += mp.getSrc(iterationByte, read)) != iterationByte.length);
		iteration = ByteBuffer.wrap(iterationByte).getInt();
		read = 0;
		while ((read += mp.getSrc(salt, read)) != salt.length);
		read = 0;
		while ((read += mp.getSrc(IV, read)) != IV.length);
		if (!(keyMetadata.iterationRange[0] <= iteration && iteration < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iteration + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherMetadata().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iteration), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}

}
