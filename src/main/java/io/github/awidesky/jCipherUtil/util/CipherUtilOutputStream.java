package io.github.awidesky.jCipherUtil.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Optional;

import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.util.cipherEngine.CipherEngine;

/**
 * A {@code CipherUtilOutputStream} serves as a layer on top of underlying {@code OutputStream}
 * to provide additional encryption/decryption process.<p>
 * In other words, {@code CipherUtilOutputStream} encrypts/decrypts given data (with a {@code CipherEngine}
 * which is initiated earlier with proper {@code CipherMode}), and writes to the underlying {@code OutputStream}.
 * <p>
 * 
 * It is recommended to generating {@code CipherUtilOutputStream} by
 * {@code CipherUtil#outputStream(OutputStream, io.github.awidesky.jCipherUtil.CipherMode)}.<p>
 * 
 * Note : this outputStream is NOT thread safe - attempt to write with one instance from multiple threads
 * (in my opinion you shouldn't, by the way), may produce unexpected behavior.
 * 
 * @see CipherUtil#outputStream(OutputStream, io.github.awidesky.jCipherUtil.CipherMode)
 */
public class CipherUtilOutputStream extends FilterOutputStream {

	private final CipherEngine cipher;
	private boolean closed = false;
	
	/**
	 * Construct {@code CipherUtilOutputStream} with given {@code OutputStream} and
	 * {@code CipherEngine}.
	 * <p>
	 * Even though using this constructor is a valid way to construct a {@code CipherUtilOutputStream},
	 * {@code CipherUtil#outputStream(OutputStream, io.github.awidesky.jCipherUtil.CipherMode)}
	 * is the recommended way to create {@code CipherUtilOutputStream},
	 * 
	 * @see CipherUtil#outputStream(OutputStream, io.github.awidesky.jCipherUtil.CipherMode) 
	 * @param out the to-be-processed {@code OutputStream}
	 * @param cipher a {@code CipherEngine} to do the cipher process
	 */
	public CipherUtilOutputStream(OutputStream out, CipherEngine cipher) {
		super(out);
		this.cipher = cipher;
	}

	/**
     * Writes the given byte to this OutputStream.
     *
     * @param b given <code>byte</code>.
     * @exception IOException if an I/O error occurs.
     */
	@Override
	public void write(int b) throws IOException {
		write(new byte[] { (byte)b });
	}

    /**
     * Writes all bytes from the given byte array to this OutputStream.
     * <p>
     * The {@code CipherUtilOutputStream#write(byte[])} method calls
     * the {@code CipherUtilOutputStream#write(byte[], int, int)} with
     * {@code b}, {@code 0}, and {@code b.length}.
     *
     * @param b the data.
     * @exception IOException if an I/O error occurs.
     * @see CipherUtilOutputStream#write(byte[], int, int)
     */
	@Override
	public void write(byte[] b) throws IOException {
		write(b, 0, b.length);
	}

    /**
     * Writes {@code len} bytes from the given byte array
     * starting at offset {@code off} to this OutputStream.
     *
     * @param b the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @exception IOException if an I/O error occurs.
     */
	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if(closed) throw new IOException("stream closed");
		out.write(Optional.ofNullable(cipher.update(b, off, len)).orElse(new byte[0]));
	}
	
	/**
	 * Returns the cipher mode of the {@code CipherUtilOutputStream}
	 * @return the cipher mode of the {@code CipherUtilOutputStream}
	 */
	public CipherMode mode() { return cipher.mode(); }

	/**
	 * Finish the cipher process, write the final cipher output,
	 * closes the underlying OutputStream, and mark this Stream as closed.<p>
	 * 
	 * This method flushes the underlying OutputStream before closing it.
	 * 
	 * @throws IOException If one is thrown when closing the underlying OutputStream.
	 */
	@Override
	public void close() throws IOException {
		if (closed) {
			return;
		}
		out.write(Optional.ofNullable(cipher.doFinal()).orElse(new byte[0]));
		super.flush();
		super.close();
		closed = true;
	}

}
