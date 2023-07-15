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
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

/**
 * Provides a tunnel between {@code MessageProvider} and {@code MessageConsumer}
 * The buffer size is defined in {@code AbstractCipherUtil#BUFFER_SIZE}
 * */
public abstract class CipherTunnel {
	
	final protected Cipher c;
	final protected MessageProvider mp;
	final protected MessageConsumer mc;
	final byte[] buf;
	
	public CipherTunnel(Cipher c, MessageProvider mp, MessageConsumer mc, int bufferSize) {
		this.c = c;
		this.mp = mp;
		this.mc = mc;
		this.buf = new byte[bufferSize];
	}
	
	public abstract int transfer();
	public abstract int transferFinal();
}
