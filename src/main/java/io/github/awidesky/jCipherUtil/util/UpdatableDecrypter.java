/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.util;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.messageInterface.MessageProvider;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

/**
 * An {@code UpdatableDecrypter} allows user to continuously receive fractions of decrypted data.
 * In contrast to {@code CipherUtil#decrypt(MessageProvider, MessageConsumer)},
 * {@code UpdatableDecrypter} can continue a multiple-part decryption with {@code UpdatableDecrypter#update()} method.
 * <p>
 * The instance of this class is irrelevant from {@code CipherUtil} instance that provided it via {@code CipherUtil#UpdatableDecryptCipher(MessageProvider)}.
 * Every metadata and cipher algorithm follows those of the {@code CipherUtil} instance, but calling {@code update()} and {@code doFinal()} will not affect it.
 *    
 * @see CipherUtil#UpdatableDecryptCipher(MessageProvider)
 * */
public class UpdatableDecrypter {
	
	final private Cipher c;
	final private MessageProvider mp;
	final private byte[] buf;
	private boolean finished = false;
	
	/**
	 * Creates updatable decrypter with given {@code javax.crypto.Cipher} and {@code MessageProvider}.
	 * <p>
	 * Even though this constructor is a valid way, {@code CipherUtil#UpdatableDecryptCipher(MessageProvider)} is recommended 
	 * way to create {@code UpdatableDecrypter},
	 * 
	 * @see CipherUtil#UpdatableDecryptCipher(MessageProvider)
	 * */
	public UpdatableDecrypter(Cipher c, MessageProvider mp, int bufferSize) {
		this.c = c;
		this.mp = mp;
		this.buf = new byte[bufferSize];
	}
	
	/**
	 * Continues the multiple-part decryption operation.
	 * Source data is read and decrypted(call {@code getBufferSize()} to see how many bytes are read),
	 * then decrypted data is returned.
	 *  
	 * If decryption process is finished, this method returns {@code null}.
	 * */
	public byte[] update() {
		if(finished) return null;
		
		int read = mp.getSrc(buf);
		if(read == -1) {
			byte[] ret;
			try {
				ret = c.doFinal();
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new OmittedCipherException(e);
			}
			finished = true;
			return ret;
		}
		return Optional.ofNullable(c.update(buf, 0, read)).orElse(new byte[0]);
		//return c.update(buf, 0, read);
	}
	
	/**
	 * Finishes a multiple-part decryption operation.
	 * 
	 * @return If there's remaining decrypted data, else {@code null}.
	 */
	public byte[] doFinal() {
		if(finished) return null;
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		while(true) {
			byte[] b = update();
			if(b == null) break;
			bao.writeBytes(b);
		}
		finished = true;
		return bao.toByteArray();
	}
	
	/**
	 * @return How many(in maximum) byte are returned each {@code update()} call. 
	 * */
	public int getBufferSize() { return buf.length; }
	
	/**
	 * Closes the decryption operation and releases any resources associated with the decrypter. 
	 * */
	public void close() {
		mp.close();
	}
}
