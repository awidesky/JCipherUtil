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
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.NestedOmittedCipherException;

public abstract class AbstractAESCipherUtil extends AbstractCipherUtil {

	public final static int SALT_BYTE_LENGTH = 64;
	
	protected byte[] IV;
	

	protected AbstractAESCipherUtil(CipherProperty metadata, int bufferSize) { super(metadata, bufferSize); }
	
	
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
		byte[] salt = new byte[SALT_BYTE_LENGTH]; 
		int iteration;
		
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(IV);
		sr.nextBytes(salt);
		/**
		 * https://en.wikipedia.org/wiki/PBKDF2
		 * TODO : In 2023, OWASP recommended to use 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512.
		 */
		iteration = sr.nextInt(800000, 1000000);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherMetadata(), salt, iteration), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException  e) {
			throw new NestedOmittedCipherException(e);
		}
		mc.consumeResult(IV);
		mc.consumeResult(salt);
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iteration).array());
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		IV = new byte[getCipherMetadata().NONCESIZE];
		byte[] salt = new byte[SALT_BYTE_LENGTH]; 
		int iteration;
		byte[] iterationByte = new byte[4];
		
		int read = 0;
		while ((read += mp.getSrc(IV, read)) != IV.length);
		read = 0;
		while ((read += mp.getSrc(salt, read)) != salt.length);
		read = 0;
		while ((read += mp.getSrc(iterationByte, read)) != iterationByte.length);
		iteration = ByteBuffer.wrap(iterationByte).getInt();
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherMetadata(), salt, iteration), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new NestedOmittedCipherException(e);
		}
	}

}
