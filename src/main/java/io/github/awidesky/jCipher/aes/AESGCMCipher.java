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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipher.AbstractCipher;
import io.github.awidesky.jCipher.dataIO.MessageConsumer;
import io.github.awidesky.jCipher.dataIO.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;

public class AESGCMCipher extends AbstractCipher {

	public final static CipherProperty METADATA = new CipherProperty("AES", "GCM", "NoPadding", "AES", 12, 256);
	public final static int GCM_TAG_LENGTH = 16;
	public final static int SALT_LENGTH = 64;
	
	public AESGCMCipher(int bufsize) {
		super(METADATA, bufsize);
	}
	
	@Override
	protected void initWrite(MessageConsumer mc) throws IOException {
		byte[] IV = new byte[METADATA.NONCESIZE];
		byte[] salt = new byte[SALT_LENGTH]; 
		int iteration;
		
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(IV);
		sr.nextBytes(salt);
		iteration = sr.nextInt(800000, 1000000);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(METADATA, salt, iteration), new GCMParameterSpec(iteration, IV));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
		
		mc.consumeResult(IV);
		mc.consumeResult(salt);
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iteration).array());
	}
	
	@Override
	protected void initRead(MessageProvider mp) throws IOException {
		byte[] IV = new byte[METADATA.NONCESIZE];
		byte[] salt = new byte[SALT_LENGTH]; 
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
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(METADATA, salt, iteration), new GCMParameterSpec(iteration, IV));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
	}

}
