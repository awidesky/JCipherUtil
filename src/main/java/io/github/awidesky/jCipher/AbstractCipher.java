/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.KeyProperty;

public abstract class AbstractCipher implements CipherUtil {

	protected KeyProperty key;
	protected Cipher cipher;
	protected final int BUFFER_SIZE;
	protected CipherProperty cipherMetadata;
	
	protected AbstractCipher(CipherProperty metadata, int bufferSize) {
		this.cipherMetadata = metadata;
		this.BUFFER_SIZE = bufferSize;
	}
	
	/**
	 * Initialize <code>Cipher</code> in encrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * 
	 * This method should do tasks like generating metadata, writing it.. etc.  
	 * @throws IOException 
	 * */
	protected abstract void initEncrypt(MessageConsumer mc) throws IOException;
	/**
	 * Initialize <code>Cipher</code> in decrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * 
	 * This method should do tasks like reading metadata.. etc.  
	 * @throws IOException 
	 * */
	protected abstract void initDecrypt(MessageProvider mp) throws IOException;


	public byte[] getSalt() { return key.getSalt(); }
	
	@Override
	public CipherUtil init(char[] password) {
		this.key = new KeyProperty(password);
		return this;
	}
	@Override
	public CipherUtil init(byte[] key) {
		this.key = new KeyProperty(key);
		return this;
	}


	@Override
	public void encrypt(MessageProvider mp, MessageConsumer mc)
			throws IOException, IllegalBlockSizeException, BadPaddingException {
		initEncrypt(mc);
		processCipher(mp, mc);
		mc.closeResource();
		mp.closeResource();
	}

	@Override
	public void decrypt(MessageProvider mp, MessageConsumer mc)
			throws IOException, IllegalBlockSizeException, BadPaddingException {
		initDecrypt(mp);
		processCipher(mp, mc);
		mc.closeResource();
		mp.closeResource();
	}
	
	protected void processCipher(MessageProvider mp, MessageConsumer mc) throws IOException, IllegalBlockSizeException, BadPaddingException {
		byte[] buf = new byte[BUFFER_SIZE];
		//boolean b = true; TODO
		while(true) {
			int read = mp.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipher.update(buf, 0, read);
			if(result != null) mc.consumeResult(result);
		}
		mc.consumeResult(cipher.doFinal());
	}

	@Override
	public byte[] encryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		encrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}

	@Override
	public String encryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return Base64.getEncoder().encodeToString(encryptToSingleBuffer(mp));
	}

	@Override
	public String encryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return HexFormat.of().formatHex(encryptToSingleBuffer(mp));
	}

	@Override
	public byte[] decryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		decrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}

	@Override
	public String decryptToString(MessageProvider mp, Charset encoding) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return new String(decryptToSingleBuffer(mp), encoding);
	}

	@Override
	public String decryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return Base64.getEncoder().encodeToString(decryptToSingleBuffer(mp));
	}

	@Override
	public String decryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return HexFormat.of().formatHex(decryptToSingleBuffer(mp));
	}

}
