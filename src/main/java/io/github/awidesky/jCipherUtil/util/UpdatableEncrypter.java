/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.messageInterface.MessageConsumer;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;


/**
 * An {@code UpdatableEncrypter} allows user to continuously input data to encrypt.
 * In contrast to {@code CipherUtil#encrypt(MessageProvider, MessageConsumer)},
 * {@code UpdatableEncryptera} can continue a multiple-part encryption with {@code UpdatableEncrypter#update(byte[])} method.
 * <p>
 * The instance of this class is irrelevant from {@code CipherUtil} instance that provided it via {@code CipherUtil#UpdatableEncryptCipher(MessageConsumer)}.
 * Every metadata and cipher algorithm follows those of the {@code CipherUtil} instance, but calling {@code update(byte[])} and {@code doFinal(byte[] buf)} will not affect it.   
 * @see CipherUtil#UpdatableEncryptCipher(MessageConsumer)
 * */
public class UpdatableEncrypter {

	private final Cipher c;
	private final MessageConsumer mc;
	
	/**
	 * Creates updatable encrypter with given {@code javax.crypto.Cipher} and {@code MessageConsumer}.
	 * <p>
	 * Even though this constructor is a valid way, {@code CipherUtil#UpdatableEncryptCipher(MessageConsumer)} is recommended 
	 * way to create {@code UpdatableEncrypter},
	 * 
	 * @see CipherUtil#UpdatableEncryptCipher(MessageConsumer)
	 * */
	public UpdatableEncrypter(Cipher c, MessageConsumer mc) {
		this.c = c;
		this.mc = mc;
	}
	
	/**
	 * Continues the multiple-part encryption operation.
	 * The bytes in the input buffer are processed, and the result is transferred into destination. 
	 * If input has a length of zero, this method returns {@code -1}.
	 * */
	public int update(byte[] buf) {
		return update(buf, 0, buf.length);
	}
	/**
	 * Continues the multiple-part encryption operation.
	 * The first len bytes in the input buffer, starting at off inclusive, are processed,
	 * and the result is transferred into destination. 
	 * If input has a length of zero, this method returns {@code -1}.
	 * */
	public int update(byte[] buf, int off, int len) {
		byte[] result = c.update(buf, off, len);
		if(result != null) {
			mc.consumeResult(result);
			return result.length;
		} else return -1;
	
	}
	
	/**
	 * Finishes a multiple-part encryption operation.
	 * You can also call {@code doFinal(null)} to do the same job.
	 */
	public int doFinal() {
		return doFinal(null);
	}
	/**
	 * Processes given buffer, and finishes a multiple-part encryption operation.
	 */
	public int doFinal(byte[] buf) {
		return doFinal(buf, 0, (buf == null) ? 0 : buf.length);
	}
	/**
	 * Processes given buffer, and finishes a multiple-part encryption operation.
	 * The first len bytes in the input buffer, starting at off inclusive, are processed,
	 * and the result is transferred into destination. 
	 */
	public int doFinal(byte[] buf, int off, int len) {
		try {
			byte[] result = (buf == null) ? c.doFinal() : c.doFinal(buf, off, len); 
			mc.consumeResult(result);
			return result.length;
		} catch (IllegalBlockSizeException | BadPaddingException | NestedIOException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * Finish the encryption operation and releases any resources associated with the encrypter. 
	 * */
	public void close() {
		doFinal(null);
		mc.close();
	}
}
