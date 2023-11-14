package io.github.awidesky.jCipherUtil.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import io.github.awidesky.jCipherUtil.CipherEngine;
import io.github.awidesky.jCipherUtil.CipherUtil;

/**
 * A {@code CipherUtilInputStream} serves as a layer on top of underlying {@code InputStream}
 * to provide additional encryption/decryption process.<p>
 * In other words, {@code CipherUtilInputStream} reads from the underlying {@code InputStream},
 * encrypts/decrypts data (with a {@code CipherEngine} which is initiated earlier with
 * proper {@code CipherMode}), and returns the result.<p>
 * 
 * While reading from underlying {@code InputStream} and doing cipher process, {@code CipherUtilInputStream}
 * uses two buffer. One reads data from underlying {@code InputStream}, and
 * the other stores the output of {@code CipherEngine} that isn't returned yet.
 * Initial size of both is defined in {@code CipherUtilInputStream#DEFAULT_BUFFER_SIZE}, whose value is picked
 * as random. Note that the size of the second one(output buffer) can be enlarged when there is no enough space
 * to hold the cipher output.<p>
 * 
 * It is recommended to generating {@code CipherUtilInputStream} by
 * {@code CipherUtil#inputStream(InputStream, io.github.awidesky.jCipherUtil.CipherMode)}.<p>
 * 
 * Note : this inputStream is NOT thread safe - attempt to read with one instance in multiple threads
 * (in my opinion you shouldn't, by the way), may produce unexpected behavior.
 * 
 * @see CipherUtil#inputStream(InputStream, io.github.awidesky.jCipherUtil.CipherMode)
 */
public class CipherUtilInputStream extends FilterInputStream {

	/** Default buffer size for reading from underlying InputStream. */
	public static final int DEFAULT_BUFFER_SIZE = 8 * 1024;
	
	private final CipherEngine cipher;
	private ByteBuffer outputBuffer;
	private byte[] inputBuffer;
	private boolean finished = false;
	private boolean bufStoreMode = true;
	private boolean closed = false;
	
	/**
	 * Construct {@code CipherUtilInputStream} with given {@code InputStream} and
	 * {@code CipherEngine}.
	 * <p>
	 * Even though using this constructor is a valid way to construct a {@code CipherUtilInputStream},
	 * {@code CipherUtil#inputStream(InputStream, io.github.awidesky.jCipherUtil.CipherMode)}
	 * is the recommended way to create {@code CipherUtilInputStream},
	 * 
	 * @see CipherUtil#inputStream(InputStream, io.github.awidesky.jCipherUtil.CipherMode) 
	 * @param in the to-be-processed {@code InputStream}
	 * @param cipher a {@code CipherEngine} to do the cipher process
	 */
	public CipherUtilInputStream(InputStream in, CipherEngine cipher) {
		super(in);
		this.cipher = cipher;
		outputBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE);
		inputBuffer = new byte[DEFAULT_BUFFER_SIZE];
	}

	/**
     * Reads the next byte of data from this input stream. The value
     * byte is returned as an {@code int} in the range
     * {@code 0} to {@code 255}. If no byte is available
     * because the end of the stream has been reached, the value
     * {@code -1} is returned. This method blocks until input data
     * is available, the end of the stream is detected, or an exception
     * is thrown.
     *
     * @return the next byte of data, or {@code -1} if the end of the stream is reached.
     * @exception IOException if an I/O error occurs.
     */
	@Override
	public int read() throws IOException {
		byte[] b = new byte[1];
		if(read(b) == -1) return -1;
		else return b[0];
	}

	/**
	 * Reads up to {@code b.length} bytes of data from this input stream into an
	 * array of bytes.
	 * <p>
	 * This method calls the {@code read} method of three arguments with the
	 * arguments {@code b}, {@code 0}, and {@code b.length}.
	 *
	 * @param b the buffer into which the data is read.
	 * @return the total number of bytes read into the buffer, or {@code -1} is 
	 * there is no more data because the end of the stream has been reached.
	 * @exception IOException if an I/O error occurs.
	 * @see CipherUtilInputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	/**
	 * Reads up to {@code len} bytes of data, starting from {@code off}, from this
	 * input stream into an array of bytes. This method blocks until some input is
	 * available.
	 *
	 * @param b the buffer into which the data is read.
	 * @param off the start offset off {@code b}
	 * @param len the maximum number of bytes read.
	 * @return the total number of bytes read into the buffer, or {@code -1} if
	 *         there is no more data because the end of the stream has been reached.
	 * @exception IOException if an I/O error occurs.
	 */
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

	/**
	 * Read more from underlying InputStream, process cipher, and put the output to outputBuffer.
	 * @return {@code false} if the buffer is empty, and there is no more data to read.
	 * @throws IOException if one occurs when reading from underlying InputStream.
	 */
	private boolean readMore() throws IOException {
		int read = in.read(inputBuffer);
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

	/**
	 * Set the state of the buffer to either 'store mode' or 'read mode'.<p>
	 * <ul>
	 * <li>'store mode' is when cipher-processed data should be added to the buffer.</li>
	 * <li>'read mode' is when data in the buffer should extracted to be returned to user.</li>
	 * </ul>
	 * 
	 * Before using the outputBuffer by any means(get/put data, check remaining, etc..),
	 * one must call this method with proper parameter. When store mode is desired,
	 * the buffer will be compacted to ensure maximum capacity.<p>
	 * 
	 * Note : this method is NOT thread safe(and also the main reason why the {@code CipherUtilInputStream}
	 * is not thread safe) - attempt to call this in multiple threads may cause unexpected behavior.
	 * 
	 * @param storeMode
	 */
	private void resetBuffer(boolean storeMode) {
		if(storeMode == bufStoreMode) return;
		if(storeMode) { //Buffer was read mode, now change to store
			outputBuffer.compact();
		} else { //Buffer was store mode, now change to read
			outputBuffer.flip();
		}
		bufStoreMode = !bufStoreMode;
	}

	/**
	 * Closes the underlying InputStream regardless of cipher state,
	 * and mark this Stream as finished and closed.
	 * 
	 * @throws IOException if an I/O error occurs from underlying InputStream.
	 */
	public void abort() throws IOException {
		super.close();
		finished = closed = true;
	}

	/**
	 * Returns the cipher mode of the {@code CipherUtilInputStream}
	 * 
	 * @return the cipher mode of the {@code CipherUtilInputStream}
	 */
	public CipherMode mode() { return cipher.mode(); }
	
	/**
	 * Closes the underlying InputStream, and mark this Stream as finished and closed.
	 * If the cipher process is not done yet, this method throws {@code IOException}.<p>
	 * 
	 * If desired behavior is to close the stream even when the cipher process is finished,
	 * use {@code CipherUtilInputStream#abort()}
	 * 
	 * @throws IOException If one is thrown when closing the underlying InputStream,
	 * or the cipher process has not finished yet.
	 */
	@Override
	public void close() throws IOException {
		// check if cipher is finished of the stream is already closed. If not, throw as IOException.
		if(!closed && !cipher.isFinished()) throw new IOException("Cipher process has not fully finished yet");
		abort(); //only if the cipher process is finished(
	}
	

	/**
	 * Tests if this input stream supports the {@code mark} and {@code reset}
	 * methods, which it does not.
	 *
	 * @return {@code false}, since this class does not support the {@code mark} and
	 *         {@code reset} methods.
	 * @see java.io.InputStream#mark(int)
	 * @see java.io.InputStream#reset()
	 */
    @Override
    public boolean markSupported() {
        return false;
    }
}
