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
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;


/**
 * This class allows user to manually input the buffer to encrypt continuously.
 * In contrast to {@code CipherUtil#encrypt(InPut, OutPut)},
 * {@code UpdatableEncryptera} can continue a multiple-part encryption with {@code UpdatableEncrypter#update(byte[])} method.
 *  
 * <p>The instance of this class provided via {@code CipherUtil#UpdatableEncryptCipher(OutPut)} is irrelevant from {@code CipherUtil} instance who returned it.
 * Every metadata(key, salt, etc...) and cipher/key algorithms are same with those of the {@code CipherUtil} instance, but those two each has totally separated cipher process.   
 * @see CipherUtil#UpdatableEncryptCipher(OutPut)
 * */
public class UpdatableEncrypter {

	private final Cipher c;
	private final OutPut out;
	
	/**
	 * Instantiate a new updatable encrypter that uses given {@code javax.crypto.Cipher} and writes to given output.
	 * Given {@code javax.crypto.Cipher} instant must be initiated with proper metadata and key before passed.
	 * <p>
	 * This constructor is not intended to be called directly on user's side. Using
	 * {@code AbstractCipherUtil#UpdatableEncryptCipher(OutPut)} is recommended.
	 * 
	 * @param c a {@code javax.crypto.Cipher} that is already initiated({@code Cipher.init} method must be called before passing it) as encryption mode.
	 * @param out output destination to store encrypted data.
	 */
	public UpdatableEncrypter(Cipher c, OutPut out) {
		this.c = c;
		this.out = out;
	}
	
	/**
	 * Encrypt given buffer and write to the output.
	 * 
	 * @param buf data to be encrypted.
	 * @return amount of encrypted data written to the output. May different from size of the input buffer.
	 */
	public int update(byte[] buf) {
		byte[] result = c.update(buf);
		if(result != null) out.consumeResult(result);
		return result.length;
	}
	/**
	 * Finish the cipher process and writes final output.
	 * If given buffer is not a {@code null}, process it. After that, finish the cipher process and writes
	 * final result to the output.
	 *  
	 * @param buf last part of data to be encrypted. <code>null</code> is permitted if there's no data to encrypt at the moment.
	 * @return amount of encrypted data written to the output. May different from size of the input buffer.
	 */
	public int doFinal(byte[] buf) {
		try {
			byte[] result = (buf == null) ? c.doFinal() : c.doFinal(buf); 
			out.consumeResult(result);
			return result.length;
		} catch (IllegalBlockSizeException | BadPaddingException | NestedIOException e) {
			throw new OmittedCipherException(e);
		}
	}
}
