/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.dataIO;

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

public interface MessageProvider {
	/**
	 * Reads from Source data(may be a plainText or cipherText) and fills the buffer
	 * 
	 * @param buffer buffer to store read data
	 * @return the total number of bytes read into the buffer, or -1 if there is no more data
	 * 
	 * */
	public default int getSrc(byte[] buffer) throws IOException { return getSrc(buffer, 0); }
	/**
	 * Reads from Source data(may be a plainText or cipherText) and fills the buffer
	 * 
	 * @param buffer buffer to store read data
	 * @param off   the start offset in array {@code buffer}
     *              at which the data is written.
	 * 
	 * 
	 * @return the total number of bytes read into the buffer, or -1 if there is no more data
	 * 
	 * */
	public int getSrc(byte[] buffer, int off) throws IOException;
	
	

	public static MessageProvider from(byte[] src) {
		return from(new ByteArrayInputStream(src));
	}
	public static MessageProvider from(File src) throws FileNotFoundException {
		return from(new FileInputStream(src));
	}
	public static MessageProvider from(String src) {
		return from(src, Charset.defaultCharset());
	}
	public static MessageProvider fromBase64(String base64) {
		return from(Base64.getDecoder().decode(base64));
	}
	public static MessageProvider fromHexString(String hex) {
		return from(HexFormat.of().parseHex(hex.toLowerCase()));
	}
	public static MessageProvider from(String src, Charset encoding) {
		return from(new ByteArrayInputStream(src.getBytes(encoding)));
	}
	public static MessageProvider from(InputStream src) {
		return new MessageProvider() {
			private InputStream in = src;
			@Override
			public int getSrc(byte[] buffer, int off) throws IOException {
				try {
					return in.read(buffer, off, buffer.length - off);
				} catch (Exception e) {
					in.close();
					throw e;
				}
			}
		};
	}
	
	/**
	 * Read specific length of a <code>Stream</code> and provide.
	 * Returned <code>MessageProvider</code> does not close <code>InputStream</code> if <code>len</code> bytes are successfully read
	 * */
	public static MessageProvider from(InputStream src, long len) {
		return new MessageProvider() {
			private InputStream in = src;
			private long length = len;
			@Override
			public int getSrc(byte[] buffer, int off) throws IOException {
				try {
					int read = in.read(buffer, off, (int)Math.min(buffer.length - off, length));
					if(read == -1) in.close();
					else {
						length -= read;
						if(length == 0) return -1;
					}
					return read;
				} catch (Exception e) {
					in.close();
					throw e;
				}
			}
		};
	}
	public static MessageProvider from(ReadableByteChannel src) {
		return new MessageProvider() {
			private ReadableByteChannel in = src;
			@Override
			public int getSrc(byte[] buffer, int off) throws IOException {
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer).position(off);
					return in.read(buf);
				} catch (Exception e) {
					in.close();
					throw e;
				}
			}
		};
	}
	/**
	 * Read specific length of a <code>ReadableByteChannel</code> and provide.
	 * Returned <code>MessageProvider</code> does not close <code>ReadableByteChannel</code> if <code>len</code> bytes are successfully read
	 * */
	public static MessageProvider from(ReadableByteChannel src, long len) {
		return new MessageProvider() {
			private ReadableByteChannel in = src;
			private long length = len;
			
			@Override
			public int getSrc(byte[] buffer, int off) throws IOException {
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer).position(off).limit((int)Math.min(buffer.length, length + off));
					int read = in.read(buf);
					if(read == -1) in.close();
					else {
						length -= read;
						if(length == 0) return -1;
					}
					return read;
				} catch (Exception e) {
					in.close();
					throw e;
				}
			}
		};
	}
	
}
