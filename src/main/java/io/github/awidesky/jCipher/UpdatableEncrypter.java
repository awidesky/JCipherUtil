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

import io.github.awidesky.jCipher.messageInterface.MessageConsumer;

public abstract class UpdatableEncrypter {

	final protected Cipher c;
	final protected MessageConsumer mc;
	final int bufferSize;
	
	public UpdatableEncrypter(Cipher c, MessageConsumer mc, int bufferSize) {
		this.c = c;
		this.mc = mc;
		this.bufferSize = bufferSize;
	}
	
	public abstract int update(byte[] buf);
	public abstract int doFinal(byte[] buf);
}
