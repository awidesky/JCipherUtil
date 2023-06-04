/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.aes;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.util.NestedCipherException;

public class AESGCMCipherUtil extends AbstractCipherUtil {


	public final static CipherProperty METADATA = new CipherProperty("AES", "GCM", "NoPadding", "AES", 12, 256);
	public final static int GCM_TAG_BIT_LENGTH = 128;
	public final static int SALT_BYTE_LENGTH = 64;
	
	private byte[] IV;
	

	public AESGCMCipherUtil(int bufferSize) {
		super(METADATA, bufferSize);
	}
	
	/**
	 * Return copy of Initial Vector
	 * @Deprecated probably no use, an cause confusion to figure out since returning IV is used in previous cipher task
	 * */
	@Deprecated
	public byte[] getIV() { return Arrays.copyOf(IV, IV.length); }
	
	@Override
	protected void initEncrypt(MessageConsumer mc) throws IOException {
		IV = new byte[METADATA.NONCESIZE];
		byte[] salt = new byte[SALT_BYTE_LENGTH]; 
		int iteration;
		
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(IV);
		sr.nextBytes(salt);
		iteration = sr.nextInt(800000, 1000000);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(METADATA, salt, iteration), new GCMParameterSpec(GCM_TAG_BIT_LENGTH, IV));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new NestedCipherException(e);
		}
		mc.consumeResult(IV);
		mc.consumeResult(salt);
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iteration).array());
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws IOException {
		IV = new byte[METADATA.NONCESIZE];
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
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(METADATA, salt, iteration), new GCMParameterSpec(GCM_TAG_BIT_LENGTH, IV));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new NestedCipherException(e);
		}
	}

	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected CipherProperty getCipherMetadata() { return METADATA; }

}
