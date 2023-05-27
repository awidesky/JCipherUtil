/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipher.dataIO.MessageConsumer;
import io.github.awidesky.jCipher.dataIO.MessageProvider;
import io.github.awidesky.jCipher.metadata.KeyProperty;

	
public interface CipherUtil {
	/**
	 * Initialize this <code>CipherUtil</code> with given <code>password</code>
	 * */
	public void init(char[] password);
	/**
	 * Initialize this <code>CipherUtil</code> with given <code>password</code>
	 * Given byte array does not used directly as a key. instead, it is converted to <code>String</code> via {@link KeyProperty#byteArrToCharArr},
	 * and then used as a password.
	 * This is for consistency of salting, PBE algorithm, cipher metadata save protocol.
	 * */
	public void init(byte[] password);

	/**
	 * Simple way to encrypt from a source to a destination.
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc CipherUtil data Consumer that writes encrypted data to designated destination 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public void encrypt(MessageProvider mp, MessageConsumer mc) throws IOException, IllegalBlockSizeException, BadPaddingException;
	/**
	 * Simple way to decrypt from a source to a destination.
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @param mc Plain data Consumer that writes decrypted data to designated destination 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public void decrypt(MessageProvider mp, MessageConsumer mc) throws IOException, IllegalBlockSizeException, BadPaddingException;
	
	
	/**
	 * Encrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp Plain dataProvider of source for encryption
	 * @return the <code>byte</code> array that has all encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public byte[] encryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
	/**
	 * Encrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp Plain dataProvider of source for encryption
	 * @return <code>Base64</code> text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public String encryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
	/**
	 * Encrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp Plain dataProvider of source for encryption
	 * @return hex format text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public String encryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
	
	
	/**
	 * Decrypts whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return the <code>byte</code> array that has all decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public byte[] decryptToSingleBuffer(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
	/**
	 * Decrypts whole data and encode it to <code>String</code>
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return text that encoded from decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public String decryptToString(MessageProvider mp, Charset encoding) throws IllegalBlockSizeException, BadPaddingException, IOException;
	/**
	 * Decrypts whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return <code>Base64</code> text that encoded from decrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public String decryptToBase64(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
	/**
	 * Decrypts whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return hex format text that encoded from encrypted data
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * */
	public String decryptToHexString(MessageProvider mp) throws IllegalBlockSizeException, BadPaddingException, IOException;
}