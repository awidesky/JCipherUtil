package io.github.awidesky.jCipherUtil.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEngine;

public class CipherUtilOutputStream extends FilterOutputStream {

	private final CipherEngine cipher;
	
	public CipherUtilOutputStream(OutputStream out, CipherUtil cipher, CipherUtil.CipherMode mode) {
		super(out);
		this.cipher = cipher.cipherEngine(mode);
	}

	@Override
	public void write(int b) throws IOException {
		write(new byte[] { (byte)b });
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		out.write(cipher.update(b, off, len));
	}

	@Override
	public void close() throws IOException {
		cipher.doFinal();
		flush();
		super.close();
	}

}
