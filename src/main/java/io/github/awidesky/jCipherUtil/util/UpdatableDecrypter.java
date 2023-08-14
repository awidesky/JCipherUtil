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

import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public class UpdatableDecrypter {
	
	final private Cipher c;
	final private InPut mp;
	final private byte[] buf;
	
	public UpdatableDecrypter(Cipher c, InPut mp, int bufferSize) {
		this.c = c;
		this.mp = mp;
		this.buf = new byte[bufferSize];
	}
	
	public byte[] update() {
		int read = mp.getSrc(buf);
		if(read == -1) return null;
		return c.update(buf, 0, read);
	}
	
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
