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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import io.github.awidesky.jCipher.AbstractCipher;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;

public class AESGCMCipher extends AbstractCipher {

	public final static CipherProperty METADATA = new CipherProperty("AES", "GCM", "NoPadding", "AES", 12, 256);
	public final static int GCM_TAG_BIT_LENGTH = 128;
	public final static int SALT_BYTE_LENGTH = 64;
	
	private byte[] IV;
	
	public AESGCMCipher(int bufsize) {
		super(METADATA, bufsize);
		try {
			cipher = Cipher.getInstance(METADATA.ALGORITMH_NAME + "/" + METADATA.ALGORITMH_MODE + "/" + METADATA.ALGORITMH_PADDING);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public byte[] getIV() { return IV; }
	
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
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
		/*
		System.out.println("Encrypt : ");
		System.out.println("salt : " + HexFormat.of().formatHex(salt));
		System.out.println("iter : " + iteration);
		System.out.println("IV : " + HexFormat.of().formatHex(IV));
		*/
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
		/*
		System.out.println("Decrypt : ");
		System.out.println("salt : " + HexFormat.of().formatHex(salt));
		System.out.println("iter : " + iteration);
		System.out.println("IV : " + HexFormat.of().formatHex(IV));
		*/
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(METADATA, salt, iteration), new GCMParameterSpec(GCM_TAG_BIT_LENGTH, IV));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| InvalidKeySpecException e) {
			e.printStackTrace();
			return;
		}
	}

}
