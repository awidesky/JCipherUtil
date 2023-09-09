/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.messageInterface;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HexFormat;

import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;

/**
 * An Interface that abstracts providing cipher source data from various sources(e.g. byte array, a file, Base64 encoded text, an <code>InputStream</code> etc.).
 * <p>This interface does not care if the data is encryped, decrypted, or not.
 * */
public interface InPut extends AutoCloseable {
	/**
	 * Reads bytes from the input source(e.g. byte array, a file, Base64 encoded text, an <code>InputStream</code> etc.)
	 * into an array of bytes. An attempt is made to read until the buffer is full,
	 * but a smaller number may be read. The number of bytes actually read is returned as an integer.
	 * 
	 * @param buffer buffer to store read data
	 * @return the total number of bytes read into the buffer(may be smaller than the buffer's length), or -1 if there is no more data
	 * */
	public default int getSrc(byte[] buffer) throws NestedIOException { return getSrc(buffer, 0); }
	/**
	 * Reads bytes from the input source(e.g. byte array, a file, Base64 encoded text, an <code>InputStream</code> etc.)
	 * into an array of bytes, starting from given offset. An attempt is made to read until the buffer is full,
	 * but a smaller number may be read. The number of bytes actually read is returned as an integer.
	 * 
	 * @param buffer buffer to store read data
	 * @param off   the start offset in array {@code buffer}
     *              at which the data is written.
	 * @return the total number of bytes read into the buffer, or -1 if there is no more data
	 * */
	public int getSrc(byte[] buffer, int off) throws NestedIOException;
	/**
	 * Close attached resource if needed.
	 * */
	public void closeResource() throws NestedIOException; //TODO : fix this
	/**
	 * Close attached resource if needed.
	 * <p>This method just calls {@code InPut#closeResource()}
	 * */
	@Override
	public default void close() throws NestedIOException { closeResource(); }
	
	/**
	 * Returns a {@code InPut} that reads data from given byte array.
	 * 
	 * @param src source of the data
	 * */
	public static InPut from(byte[] src) {
		return from(new ByteArrayInputStream(src));
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>File</code>
	 * 
	 * @param src source of the data
	 * */
	public static InPut from(File src) throws FileNotFoundException {
		return from(new FileInputStream(src));
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>String</code>.
	 * <p>The String will be decoded with <code>Charset.defaultCharset()</code>.
	 * 
	 * @see InPut#from(String, Charset)
	 * @param str source of the data
	 * */
	public static InPut from(String str) {
		return from(str, Charset.defaultCharset());
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>String</code>.
	 * <p>The String will be decoded with <code>encoding</code>.
	 * 
	 * @param str source of the data
	 * @param encoding character set to encode the <code>String</code>
	 * */
	public static InPut from(String str, Charset encoding) {
		return InPut.from(new ByteArrayInputStream(str.getBytes(encoding)));
	}
	/**
	 * Returns a {@code InPut} that reads data from given Base64 encoded <code>String</code>
	 * 
	 * @param base64 Base64 encoded <code>String</code>
	 * */
	public static InPut fromBase64(String base64) {
		return from(Base64.getDecoder().decode(base64));
	}
	/**
	 * Returns a {@code InPut} that reads data from given Hex encoded <code>String</code>
	 * 
	 * @param hex Hex encoded <code>String</code>
	 * */
	public static InPut fromHexString(String hex) {
		return InPut.from(HexFormat.of().parseHex(hex.toLowerCase()));
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>InputStream</code>.<p>
	 * This method closes <code>InputStream</code> after the Cipher process is successfully finished
	 * 
	 * @see InPut#from(InputStream, boolean)
	 * @param src <code>InputStream</code> to source of the data
	 * */
	public static InPut from(InputStream src) {
		return from(src, true);
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>InputStream</code>
	 * 
	 * @param src <code>InputStream</code> to source of the data
	 * @param close whether close <code>InputStream</code> after the Cipher process is successfully finished
	 * */
	public static InPut from(InputStream src, boolean close) {
		return new InPut() {
			private InputStream in = src;
			@Override
			public int getSrc(byte[] buffer, int off) throws NestedIOException {
				try {
					return in.read(buffer, off, buffer.length - off);
				} catch (IOException e) {
					closeResource();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void closeResource() throws NestedIOException {
				try { if(close) in.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>InputStream</code>, 
	 * but only up to <code>len</code> bytes from the <code>InputStream</code> are provided.
	 * This method closes <code>InputStream</code> after the Cipher process is successfully finished
	 * 
	 * @see InPut#from(InputStream, long, boolean)
	 * @param src <code>InputStream</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * */
	public static InPut from(InputStream src, long len) {
		return from(src, len, true);
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>InputStream</code>, but only up to <code>len</code> bytes.
	 * 
	 * @param src <code>InputStream</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * @param close whether close <code>InputStream</code> after the Cipher process is successfully finished
	 * */
	public static InPut from(InputStream src, long len, boolean close) {
		return new InPut() {
			private InputStream in = src;
			private long length = len;
			@Override
			public int getSrc(byte[] buffer, int off) throws NestedIOException {
				if(length == 0) return -1;
				try {
					int read = in.read(buffer, off, (int)Math.min(buffer.length - off, length));
					if(read == -1) in.close();
					else  length -= read;
					
					return read;
				} catch (IOException e) {
					closeResource();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void closeResource() throws NestedIOException {
				try { if(close) in.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>ReadableByteChannel</code>
	 * This method closes <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * 
	 * @see InPut#from(ReadableByteChannel, boolean)
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * */
	public static InPut from(ReadableByteChannel src) {
		return from(src, true);
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>ReadableByteChannel</code>
	 * 
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param close whether close <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * */
	public static InPut from(ReadableByteChannel src, boolean close) {
		return new InPut() {
			private ReadableByteChannel in = src;
			@Override
			public int getSrc(byte[] buffer, int off) throws NestedIOException {
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer).position(off);
					int read = in.read(buf);
					if(read == -1) closeResource();
					return read;
				} catch (IOException e) {
					closeResource();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void closeResource() throws NestedIOException {
				try { if(close) in.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>ReadableByteChannel</code>, but only up to <code>len</code> bytes.
	 * This method closes <code>ReadableByteChannel</code> after the Cipher process is successfully finished.
	 * 
	 * @see InPut#from(ReadableByteChannel, long, boolean)
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * */
	public static InPut from(ReadableByteChannel src, long len) {
		return from(src, len, true);
	}
	/**
	 * Returns a {@code InPut} that reads data from given <code>ReadableByteChannel</code>, but only up to <code>len</code> bytes.
	 * 
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * @param close whether close <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * */
	public static InPut from(ReadableByteChannel src, long len, boolean close) {
		return new InPut() {
			private ReadableByteChannel in = src;
			private long length = len;
			
			@Override
			public int getSrc(byte[] buffer, int off) throws NestedIOException {
				if(length == 0) return -1;
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer).position(off).limit((int)Math.min(buffer.length, length + off));
					int read = in.read(buf);
					if(read == -1) in.close();
					else length -= read;

					return read;
				} catch (IOException e) {
					closeResource();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void closeResource() throws NestedIOException {
				try { if(close) in.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
	
}
