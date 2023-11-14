/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.util;

import io.github.awidesky.jCipherUtil.CipherEngine;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;

/**
 * Provides a cipher tunnel between {@code InPut} and {@code OutPut}.
 * The tunnel is not visible to outside; which means the internal cipher stream pipeline cannot be intercepted,
 * transferred data is invisible. only how many bytes are read and processed is returned from the public methods.
 * <p>
 * There are only two public methods -{@code transfer()} call does cipher I/O process
 * (reads from {@code InPut} to the buffer, do cipher update, and store result(if there is) to the {@code OutPut}) once,
 * and {@code transferFinal} repeats cipher I/O process until there is nothing left to read.
 * <p>
 * This class is designed to use in situations where blocking-until-entirely-finished methods(like {@code CipherUtil#encrypt(InPut, OutPut)}
 * and {@code CipherUtil#decrypt(InPut, OutPut)} should be avoided, allowing current thread to do other things or check the progress
 * (how much data has been processed, etc.) continuously.
 * <p>
 * If you have to intercept data during cipher process, consider using {@code UpdatableCipherInput}, {@code UpdatableCipherOutput} or {@code CipherUtilOutputStream}, {@code CipherUtilInputStream}.
 * */
public class CipherTunnel {
	
	final protected CipherEngine c;
	final protected InPut in;
	final protected OutPut out;
	final byte[] buf;
	
	private boolean finished = false;
	
	/**
	 * Create a cipher I/O tunnel between {@code InPut} and {@code OutPut}.
	 * Given {@code javax.crypto.Cipher} instant must be initiated with proper metadata and key before passed.
	 * Because of that, the {@code CipherTunnel} code can work in both mode(encrypting/decrypting) without knowing which one is it now.
	 * <p>
	 * This constructor is not intended to be called directly on user's side. Calling
	 * {@code AbstractCipherUtil#cipherEncryptTunnel(InPut, OutPut)} or {@code AbstractCipherUtil#cipherDecryptTunnel(InPut, OutPut)}
	 * is recommended.
	 * 
	 * @param c a {@code javax.crypto.Cipher} that is already initiated({@code Cipher.init} method mus be called before passing it)
	 * @param in input data to be encrypted or decrypted depending on mode of {@code c}
	 * @param out output destination to store data that is encrypted or decrypted depending on mode of {@code c}
	 * @param bufferSize value of the buffer. {@code bufferSize} amount of data will processed in one {@code CipherTunnel#transfer()} call.
	 */
	public CipherTunnel(CipherEngine c, InPut in, OutPut out, int bufferSize) {
		this.c = c;
		this.in = in;
		this.out = out;
		this.buf = new byte[bufferSize];
	}
	
	/**
	 * Tries to fill the buffer, update cipher process, and store the result if exists.
	 * 
	 * @return amount of data read and processed in bytes.
	 * 		   -1 if the cipher process is finished because there is nothing to read.
	 */
	public int transfer() {
		if(finished) return -1;
		int ret = in.getSrc(buf);
		if(ret != -1) out.consumeResult(c.update(buf,0 , ret));
		else {
			out.consumeResult(c.doFinal());
			finished = true;
		}
		return ret;
	}
	/**
	 * Repeat filling the buffer from input, update cipher process,
	 * and write the result to the output until there is nothing left to read.
	 * <p>This methods always finishes the cipher process.
	 *  
	 * @return amount of total data read and processed in bytes
	 */
	public int transferFinal() {
		if(finished) return -1;
		int read = 0;
		int total = 0;
		while(true) {
			read = transfer();
			if(read == -1) break;
			total += read;
		}
		return total;
	}
	
	/**
	 * Return whether the cipher process is finished.
	 * If it is, {@code CipherTunnel#transfer()} and {@code CipherTunnel#transferFinal()}
	 * methods will always return {@code -1}.
	 * 
	 * @return {@code true} if the cipher process is finished(every bytes of the input is processed and
	 * 		   the output is written to the output), otherwise {@code false}.
	 */
	public boolean isFinished() { return finished; }
}
