package io.github.awidesky.jCipherUtil.util.cipherEngine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;

public abstract class CipherEngine {

	protected Cipher c;
	protected CipherUtil.CipherMode mode;
	protected boolean finished = false;
	
	public CipherEngine(CipherUtil.CipherMode mode) {
		this.mode = mode;
	}
	
	public byte[] update(byte[] buf) {
		return update(buf, 0, buf.length);
	}
	public abstract byte[] update(byte[] buf, int off, int len);
	public abstract void init();
	
	public byte[] doFinal() {
		if(finished) return null;
		finished = true;
		try {
			return c.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	public byte[] doFinal(byte[] buf) {
		if(finished) return null;
		if(buf == null) return doFinal();
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		try {
			o.write(update(buf));
			o.write(doFinal());
		} catch (IOException e) {
			throw new OmittedCipherException(e);
		}
		return o.toByteArray();
	}

	public boolean isFinished() { return finished; }
}


