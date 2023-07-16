/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.messageInterface;

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

import io.github.awidesky.jCipher.util.NestedIOException;

/**
 * An Interface that abstracts providing cipher source data from various sources(e.g. byte array, a file, base64 encoded text, an <code>InputStream</code> etc.).
 * <p>This interface does not care if the data is encryped, decrypted, or not.
 * */
public interface MessageProvider extends AutoCloseable {
	/**
	 * Reads from Source data(may be a plainText or cipherText) and fills the buffer
	 * 
	 * @param buffer buffer to store read data
	 * @return the total number of bytes read into the buffer, or -1 if there is no more data
	 * */
	public default int getSrc(byte[] buffer) throws NestedIOException { return getSrc(buffer, 0); }
	/**
	 * Reads from Source data(may be a plainText or cipherText) and fills the buffer
	 * 
	 * @param buffer buffer to store read data
	 * @param off   the start offset in array {@code buffer}
     *              at which the data is written.
	 * 
	 * @return the total number of bytes read into the buffer, or -1 if there is no more data
	 * */
	public int getSrc(byte[] buffer, int off) throws NestedIOException;
	/**
	 * Close attached resource if needed.
	 * */
	public void closeResource() throws NestedIOException;
	/**
	 * Close attached resource if needed.
	 * */
	@Override
	public default void close() throws NestedIOException { closeResource(); }
	
	/**
	 * Provide data from a <code>byte[]</code>
	 * 
	 * @param src source of the data
	 * */
	public static MessageProvider from(byte[] src) {
		return from(new ByteArrayInputStream(src));
	}
	/**
	 * Provide data from a <code>File</code>
	 * 
	 * @param src source of the data
	 * */
	public static MessageProvider from(File src) throws FileNotFoundException {
		return from(new FileInputStream(src));
	}
	/**
	 * Provide data from a <code>String</code>.
	 * <p>Encode <code>String</code> with <code>Charset.defaultCharset()</code>.
	 * 
	 * @see MessageProvider#from(String, Charset)
	 * @param str source of the data
	 * */
	public static MessageProvider from(String str) {
		return from(str, Charset.defaultCharset());
	}
	/**
	 * Provide data from a <code>String</code>.
	 * <p>Encode <code>String</code> with <code>encoding</code>.
	 * 
	 * @param str source of the data
	 * @param encoding character set to encode the <code>String</code>
	 * */
	public static MessageProvider from(String str, Charset encoding) {
		return MessageProvider.from(new ByteArrayInputStream(str.getBytes(encoding)));
	}
	/**
	 * Provide data from a Base64 encoded <code>String</code>
	 * 
	 * @param base64 Base64 encoded <code>String</code>
	 * */
	public static MessageProvider fromBase64(String base64) {
		return from(Base64.getDecoder().decode(base64));
	}
	/**
	 * Provide data from a Hex encoded <code>String</code>
	 * 
	 * @param hex Hex encoded <code>String</code>
	 * */
	public static MessageProvider fromHexString(String hex) {
		return MessageProvider.from(HexFormat.of().parseHex(hex.toLowerCase()));
	}
	/**
	 * Provide data from a <code>InputStream</code>.<p>
	 * This method closes <code>InputStream</code> after the Cipher process is successfully finished
	 * 
	 * @see MessageProvider#from(InputStream, boolean)
	 * @param src <code>InputStream</code> to source of the data
	 * */
	public static MessageProvider from(InputStream src) {
		return from(src, true);
	}
	/**
	 * Provide data from <code>InputStream</code>
	 * 
	 * @param src <code>InputStream</code> to source of the data
	 * @param close whether or not close <code>InputStream</code> after the Cipher process is successfully finished
	 * */
	public static MessageProvider from(InputStream src, boolean close) {
		return new MessageProvider() {
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
	 * Provide data from a <code>InputStream</code>, 
	 * but only up to <code>len</code> bytes from the <code>InputStream</code> are provided.
	 * This method closes <code>InputStream</code> after the Cipher process is successfully finished
	 * 
	 * @see MessageProvider#from(InputStream, long, boolean)
	 * @param src <code>InputStream</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * */
	public static MessageProvider from(InputStream src, long len) {
		return from(src, len, true);
	}
	/**
	 * Provide data from <code>InputStream</code>, 
	 * but only up to <code>len</code> bytes from the <code>InputStream</code> are provided.
	 * 
	 * @param src <code>InputStream</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * @param close whether or not close <code>InputStream</code> after the Cipher process is successfully finished
	 * */
	public static MessageProvider from(InputStream src, long len, boolean close) {
		return new MessageProvider() {
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
	 * Provide data from a <code>ReadableByteChannel</code>
	 * This method closes <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * 
	 * @see MessageProvider#from(ReadableByteChannel, boolean)
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * */
	public static MessageProvider from(ReadableByteChannel src) {
		return from(src, true);
	}
	/**
	 * Provide data from <code>ReadableByteChannel</code>
	 * 
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param close whether or not close <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * */
	public static MessageProvider from(ReadableByteChannel src, boolean close) {
		return new MessageProvider() {
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
	 * Provide data from a <code>ReadableByteChannel</code>, 
	 * but only up to <code>len</code> bytes from the <code>ReadableByteChannel</code> are provided.
	 * This method closes <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * 
	 * @see MessageProvider#from(ReadableByteChannel, long, boolean)
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * */
	public static MessageProvider from(ReadableByteChannel src, long len) {
		return from(src, len, true);
	}
	/**
	 * Provide data from <code>ReadableByteChannel</code>, 
	 * but only up to <code>len</code> bytes from the <code>ReadableByteChannel</code> are provided.
	 * 
	 * @param src <code>ReadableByteChannel</code> to source of the data
	 * @param len  the maximum number of bytes to provide
	 * @param close whether or not close <code>ReadableByteChannel</code> after the Cipher process is successfully finished
	 * */
	public static MessageProvider from(ReadableByteChannel src, long len, boolean close) {
		return new MessageProvider() {
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
