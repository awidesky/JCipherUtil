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

	/**
	 * @return The salt for the key
	 * */
	public byte[] getSalt() { return key.getSalt(); }
	
	/**
	 * Initialize <code>Cipher</code> with given password
	 *
	 * @param password the password
	 * */
	@Override
	public CipherUtil init(char[] password) { //TODO : destroy previous key
		this.key = new KeyProperty(password);
		return this;
	}
	/**
	 * Initialize <code>Cipher</code> with given key.
	 * parameter <code>key</code> is encoded as hex format characters and used as password.
	 * <p><i><b>The argument byte array is not directly used as <code>SecretKey</code>!</b></i>
	 * 
	 * @see KeyProperty#KeyProperty(byte[])
	 * 
	 * @param key the byte array that will be encoded to characters and used as password
	 * */
	@Override
	public CipherUtil init(byte[] key) {
		this.key = new KeyProperty(key);
		return this;
	}


	/**
	 * Encrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link AbstractCipher#initEncrypt(MessageConsumer)},
	 * {@link AbstractCipher#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see AbstractCipher#initEncrypt(MessageConsumer)
	 * @see AbstractCipher#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException
	 * */
	@Override
	public void encrypt(MessageProvider mp, MessageConsumer mc)
			throws IOException, IllegalBlockSizeException, BadPaddingException {
		initEncrypt(mc);
		processCipher(mp, mc);
		mc.closeResource();
		mp.closeResource();
	}

	/**
	 * Decrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link AbstractCipher#initDecrypt(MessageProvider)},
	 * {@link AbstractCipher#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see AbstractCipher#initEncrypt(MessageConsumer)
	 * @see AbstractCipher#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException
	 * */
	@Override
	public void decrypt(MessageProvider mp, MessageConsumer mc)
			throws IOException, IllegalBlockSizeException, BadPaddingException {
		initDecrypt(mp);
		processCipher(mp, mc);
		mc.closeResource();
		mp.closeResource();
	}
	
	/**
	 * Do Cipher Process with pre-initiated <code>cipher</code>.
	 * 
	 * @param mp Plain data Provider of source for encryption/decryption
	 * @param mc Data Consumer that writes encrypted/decryption data to designated destination 
	 * */
	protected void processCipher(MessageProvider mp, MessageConsumer mc) throws IOException, IllegalBlockSizeException, BadPaddingException {
		byte[] buf = new byte[BUFFER_SIZE];
		while(true) {
			int read = mp.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipher.update(buf, 0, read);
			if(result != null) mc.consumeResult(result);
		}
		mc.consumeResult(cipher.doFinal());
	}

	/**
	 * Encrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return the <code>byte</code> array that has all encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public byte[] encryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		encrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}

	/**
	 * Encrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return <code>Base64</code> text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public String encryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return Base64.getEncoder().encodeToString(encryptToSingleBuffer(mp));
	}

	/**
	 * Encrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return hex format text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public String encryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return HexFormat.of().formatHex(encryptToSingleBuffer(mp));
	}

	/**
	 * Decrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return the <code>byte</code> array that has all decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public byte[] decryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		decrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}

	/**
	 * Decrypt whole data and encode it to <code>String</code>
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return text that encoded from decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public String decryptToString(MessageProvider mp, Charset encoding) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return new String(decryptToSingleBuffer(mp), encoding);
	}

	/**
	 * Decrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return <code>Base64</code> text that encoded from decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public String decryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return Base64.getEncoder().encodeToString(decryptToSingleBuffer(mp));
	}

	/**
	 * Decrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return hex format text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	@Override
	public String decryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException {
		return HexFormat.of().formatHex(decryptToSingleBuffer(mp));
	}

}
