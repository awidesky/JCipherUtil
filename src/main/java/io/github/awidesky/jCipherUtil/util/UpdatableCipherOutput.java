/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * iinlies agreement with all terms and conditions of the accoinanying
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
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;


/**
 * An {@code UpdatableCipherOutput} allows user to continuously receive fractions of data.
 * In contrast to encrypt/decrypt methods in {@code CipherUtil},
 * {@code UpdatableCipherOutput} can continue a multiple-part encryption/decryption with {@code UpdatableCipherOutput#update()} method.
 * <p>
 * {@code UpdatableCipherOutput} instance has separated cipher process from the {@code CipherUtil} instance that generated it.
 * (e.g. via {@code CipherUtil#UpdatableDecryptCipher(InPut)}) 
 * Every metadata and cipher algorithm follows those of the {@code CipherUtil} instance, but calling {@code update()} and {@code doFinal()} will not affect it.
 *    
 * @see CipherUtil#updatableOutput(InPut, boolean)
 * */
public class UpdatableCipherOutput {
	
	final private Cipher c;
	final private InPut in;
	final private byte[] buf;
	private boolean finished = false;
	
	/**
	 * Creates updatable decrypter with given {@code javax.crypto.Cipher} and {@code InPut}.
	 * <p>
	 * Even though this constructor is a valid way, {@code CipherUtil#UpdatableDecryptCipher(InPut)} is recommended 
	 * way to create {@code UpdatableCipherOutput},
	 * 
	 * @see CipherUtil#updatableOutput(InPut, boolean)
	 * */
	public UpdatableCipherOutput(Cipher c, InPut in, int bufferSize) {
		this.c = c;
		this.in = in;
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
		
		int read = in.getSrc(buf);
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
		in.close();
	}
}