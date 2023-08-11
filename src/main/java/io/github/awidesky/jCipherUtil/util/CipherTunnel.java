/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.util;

import javax.crypto.Cipher;

import io.github.awidesky.jCipherUtil.messageInterface.MessageConsumer;
import io.github.awidesky.jCipherUtil.messageInterface.MessageProvider;

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
	
	public int transfer() { return update(c, buf, mp, mc); }
	
	public int transferFinal() { //TODO : 코드 재사용? 
		int read = 0;
		int total = 0;
		while(true) {
			read = update(c, buf, mp, mc);
			if(read == -1) break;
			total += read;
		}
		total += doFinal(c, mc);
		return total;
	}
	
	protected abstract int update(Cipher cipher, byte[] buffer, MessageProvider msgp, MessageConsumer msgc);
	protected abstract int doFinal(Cipher cipher, MessageConsumer msgc);
}
