package io.github.awidesky.jCipherUtil.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;

public class CipherUtilInputStream extends FilterInputStream {

	private final UpdatableDecrypter cipher;
	private ByteBuffer buffer;
	private boolean finished = false;
	private boolean bufStoreMode = true;
	
	public CipherUtilInputStream(InputStream in, CipherUtil cipher) {
		super(in);
		this.cipher = cipher.UpdatableDecryptCipher(InPut.from(in));
		buffer = ByteBuffer.allocate(this.cipher.getBufferSize());
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
		if(buffer.remaining() >= len) {
			buffer.get(b, off, len);
			totalread = len;
		} else {
			int read = 0;
			while(totalread != len) {
				resetBuffer(false);
				int remaining = buffer.remaining();
				if (remaining != 0) {
					read = Math.min(remaining, len - totalread);
					buffer.get(b, off, read);
					totalread += read;
					off += read;
				}
				if(!readMore()) {
					if(totalread == 0) return -1;
					break;
				}
			}
			
			/*while(len > 0) {
				int left = Math.min(buffer.remaining(), len);
				buffer.get(b, off, left);
				totalread += left; off += left; len -= left;
				if(readMore() == -1) {
					totalread -= len;
					break;
				}
				resetBuffer(false);
			}*/
		}
		return totalread;
	}

	private boolean readMore() {
		byte[] arr = cipher.update();
		if(arr == null && (cipher.doFinal()) == null) {
			resetBuffer(false);
			if(buffer.remaining() == 0) {
				finished  = true;
				return false;
			} else { return true; }
		}
		resetBuffer(true);
		//if remaining capacity is not enough
		if(buffer.remaining() < arr.length) {
			buffer = ByteBuffer.allocate(buffer.capacity() + arr.length).put(buffer.flip());
			bufStoreMode = true;
		}
		
		buffer.put(arr);
		return true;
	}

	private void resetBuffer(boolean storeMode) {
		
		if(storeMode == bufStoreMode) return;
		if(storeMode) { //Buffer was get mode, now change to put
			buffer.compact();
		} else { //Buffer was put mode, now change to get
			buffer.flip();
		}
		bufStoreMode = !bufStoreMode;
	}

	
	@Override
	public void close() throws IOException {
		super.close();
	}
}
