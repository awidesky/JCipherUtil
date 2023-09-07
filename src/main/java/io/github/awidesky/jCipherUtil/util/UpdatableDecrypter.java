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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;

/**
 * This class allows user to manually input the buffer to decrypt continuously.
 * In contrast to {@code CipherUtil#decrypt(InPut, OutPut)},
 * {@code UpdatableDecrypter} can continue a multiple-part decryption with {@code UpdatableDecrypter#update()} method.
 *  
 * <p>The instance of this class provided via {@code CipherUtil#UpdatableDecryptCipher(InPut)} is irrelevant from {@code CipherUtil} instance who returned it.
 * Every metadata(key, salt, etc...) and cipher/key algorithms are same with those of the {@code CipherUtil} instance, but those two each has totally separated cipher process.   
 * @see CipherUtil#UpdatableDecryptCipher(InPut)
 * */
public class UpdatableDecrypter {
	
	final private Cipher c;
	final private InPut in;
	final private byte[] buf;
	
	/**
	 * Instantiate a new updatable decrypter that uses given {@code javax.crypto.Cipher} and writes to given output.
	 * Given {@code javax.crypto.Cipher} instant must be initiated with proper metadata and key before passed.
	 * <p>
	 * This constructor is not intended to be called directly on user's side. Using
	 * {@code AbstractCipherUtil#UpdatableDecryptCipher(InPut)} is recommended.
	 * 
	 * @param c a {@code javax.crypto.Cipher} that is already initiated({@code Cipher.init} method must be called before passing it) as decryption mode.
	 * @param in input destination to read encrypted data.
	 * @param bufferSize size of a buffer used to read from the input. output buffer from {@code UpdatableDecrypter#update()} may or may not have the same length.
	 */
	public UpdatableDecrypter(Cipher c, InPut in, int bufferSize) {
		this.c = c;
		this.in = in;
		this.buf = new byte[bufferSize];
	}
	
	/**
	 * Read encrypted data from the input, process it, and return the output.
	 * <ㅔ>
	 * Size of the output buffer may be different from the size of internal buffer, or it could even be
	 * an empty array if there is no output(when the underlying cipher is a block cipher and the input data
	 * is too short to result in a new block).
	 * <ㅔ>
	 * If there is no data left in the input, this method returns {@code null}.
	 * 
	 * @return the new buffer with the result(may be empty), or {@code null} if there is no more encrypted data to process.
	 */
	public byte[] update() {
		int read = in.getSrc(buf);
		if(read == -1) return null;
		return c.update(buf, 0, read); //TODO : null means output is ended. empty array should returned!
	}
	
	/**
	 * Finish the decryption process after decrypting every data left in the input, and return the result.
	 * <p>
	 * This method does not finish the cipher process with data left on the input. It reads all the data until
	 * there is nothing left in the input, process all of them, finishes the decryption process, and return an byte array that
	 * holds the output.
	 * <p>
	 * {@code UpdatableDecrypter#update()} call made after invocation of this method will always return {@code null} since
	 * there is nothing left to read.
	 * 
	 * @return the new buffer with the total result(may be empty), or {@code null} if there is no more encrypted data to process.
	 */
	public byte[] doFinal() {
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		while(true) {
			byte[] b = update();
			if(b == null) break;
			bao.writeBytes(b);
		}
		try {
			bao.writeBytes(c.doFinal());
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
		return bao.toByteArray();
	}
}
