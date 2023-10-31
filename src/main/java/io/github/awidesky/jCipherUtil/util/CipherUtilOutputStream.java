package io.github.awidesky.jCipherUtil.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Optional;

import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEngine;

public class CipherUtilOutputStream extends FilterOutputStream {

	private final CipherEngine cipher;
	private boolean closed = false;
	
	public CipherUtilOutputStream(OutputStream out, CipherEngine cipher) {
		super(out);
		this.cipher = cipher;
	}

	@Override
	public void write(int b) throws IOException {
		write(new byte[] { (byte)b });
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if(closed) throw new IOException("stream closed");
		out.write(Optional.ofNullable(cipher.update(b, off, len)).orElse(new byte[0]));
	}

	@Override
	public void close() throws IOException {
		 if (closed) {
             return;
         }
         closed = true;
		write(Optional.ofNullable(cipher.doFinal()).orElse(new byte[0]));
		flush();
		super.close();
	}

}
