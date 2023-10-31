package io.github.awidesky.jCipherUtil.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEngine;

/**
 * {@code Cipher}
 */
public class CipherUtilInputStream extends FilterInputStream {

	public static int DEFAULT_BUFFER_SIZE = 8 * 1024;
	
	private final CipherEngine cipher;
	private ByteBuffer outputBuffer;
	private byte[] inputBuffer;
	private boolean finished = false;
	private boolean bufStoreMode = true;
	private InputStream is;
	
	public CipherUtilInputStream(InputStream in, CipherEngine cipher) {
		super(in);
		is = in;
		this.cipher = cipher;
		outputBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE);
		inputBuffer = new byte[DEFAULT_BUFFER_SIZE];
	}

	@Override
	public int read() throws IOException {
		byte[] b = new byte[1];
		if(read(b) == -1) return -1;
		else return b[0];
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if(finished) return -1;
		resetBuffer(false);
		int totalread = 0;
		if(outputBuffer.remaining() >= len) {
			outputBuffer.get(b, off, len);
			totalread = len;
		} else {
			int read = 0;
			while(totalread != len) {
				resetBuffer(false);
				int remaining = outputBuffer.remaining();
				if (remaining != 0) {
					read = Math.min(remaining, len - totalread);
					outputBuffer.get(b, off, read);
					totalread += read;
					off += read;
				}
				if(!readMore()) {
					if(totalread == 0) return -1;
					break;
				}
			}
		}
		return totalread;
	}

	private boolean readMore() throws IOException {
		int read = is.read(inputBuffer);
		byte[] arr = read != -1 ? cipher.update(inputBuffer, 0, read) : cipher.doFinal();
		if(arr == null) {
			resetBuffer(false);
			if(outputBuffer.remaining() == 0) {
				finished = true;
				return false;
			} else { return true; }
		}
		resetBuffer(true);
		//if remaining capacity is not enough
		if(outputBuffer.remaining() < arr.length) {
			outputBuffer = ByteBuffer.allocate(outputBuffer.capacity() + arr.length).put(outputBuffer.flip());
			bufStoreMode = true;
		}
		
		outputBuffer.put(arr);
		return true;
	}

	private void resetBuffer(boolean storeMode) {
		if(storeMode == bufStoreMode) return;
		if(storeMode) { //Buffer was get mode, now change to put
			outputBuffer.compact();
		} else { //Buffer was put mode, now change to get
			outputBuffer.flip();
		}
		bufStoreMode = !bufStoreMode;
	}

	public void abort() {
		cipher.doFinal();
	}
	
	@Override
	public void close() throws IOException {
		if(cipher.doFinal() != null) throw new IOException("Cipher process has not done yet");
		super.close();
	}
}
