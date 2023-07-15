/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import javax.crypto.Cipher;

import io.github.awidesky.jCipher.messageInterface.MessageProvider;

public abstract class UpdatableDecrypter {
	
	final protected Cipher c;
	final protected MessageProvider mp;
	final byte[] buf;
	
	public UpdatableDecrypter(Cipher c, MessageProvider mp, int bufferSize) {
		this.c = c;
		this.mp = mp;
		this.buf = new byte[bufferSize];
	}
	
	public abstract byte[] update();
	public abstract byte[] doFinal();
}
