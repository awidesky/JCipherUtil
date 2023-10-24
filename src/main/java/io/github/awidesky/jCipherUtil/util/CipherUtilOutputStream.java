package io.github.awidesky.jCipherUtil.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import io.github.awidesky.jCipherUtil.CipherUtil;

public class CipherUtilOutputStream extends FilterOutputStream {

	private final UpdatableCipherInput cipher;
	
	public CipherUtilOutputStream(OutputStream out, CipherUtil cipher) {
		super(out);
		this.cipher = cipher.updatableInput(null, null);
		//this.cipher = cipher.updatableInput(OutPut.to(out), CipherUtil.);
	}

	@Override
	public void write(int b) throws IOException {
		write(new byte[] { (byte)b });
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		cipher.update(b, off, len);
	}

	@Override
	public void close() throws IOException {
		cipher.doFinal(null);
		flush();
		super.close();
	}

}
