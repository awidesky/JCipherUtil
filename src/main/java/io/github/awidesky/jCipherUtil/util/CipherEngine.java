package io.github.awidesky.jCipherUtil.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipherUtil.CipherUtil;

public abstract class CipherEngine {

	protected Cipher c;
	protected CipherUtil.CipherMode mode;
	
	public CipherEngine(CipherUtil.CipherMode mode) {
		this.mode = mode;
	}
	
	public abstract byte[] update(byte[] buf);
	public abstract void init();
	
	public byte[] doFinal(byte[] buf) {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		try {
			o.write(update(buf));
			o.write(c.doFinal());
		} catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return o.toByteArray();
	}

}


