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
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;


/**
 *  This class allows user to manually input the buffer to encrypt multiple times.
 *  In contrast to {@code CipherUtil#encrypt(InPut, OutPut)},
 *  {@code UpdatableEncryptera} can continue a multiple-part encryption with {@code UpdatableEncrypter#update(byte[])} method.
 *  
 *  <p>The instance of this class is irrelevant from {@code CipherUtil} instance that provided it via {@code CipherUtil#UpdatableEncryptCipher(OutPut)}.
 *  Every metadata and cipher algorithm follows those of the {@code CipherUtil} instance, but calling {@code update(byte[])} and {@code doFinal(byte[] buf)} will not affect it.   
 *  @see CipherUtil#UpdatableEncryptCipher(OutPut)
 * */
public class UpdatableEncrypter {

	private final Cipher c;
	private final OutPut mc;
	
	public UpdatableEncrypter(Cipher c, OutPut mc) {
		this.c = c;
		this.mc = mc;
	}
	
	public int update(byte[] buf) {
		byte[] result = c.update(buf);
		if(result != null) mc.consumeResult(result);
		return result.length;
	}
	public int doFinal(byte[] buf) {
		try {
			byte[] result = (buf == null) ? c.doFinal() : c.doFinal(buf); 
			mc.consumeResult(result);
			return result.length;
		} catch (IllegalBlockSizeException | BadPaddingException | NestedIOException e) {
			throw new OmittedCipherException(e);
		}
	}
}
