/*	
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.messageInterface;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;


/**
 * An Interface that abstracts consuming cipher result and send to various destinations(e.g. byte array, a file, base64 encoded text, an <code>OutputStrea</code> etc.).
 * <p>This interface does not care if the data is encryped, decrypted, or not.
 * */
public interface MessageConsumer extends AutoCloseable {

	/**
	 * Consume data(may be a plainText or cipherText) and writes to the destination(may be a <code>String</code>, <code>File</code>, <code>OutPutStream</code> etc.)
	 * 
	 * @param buffer the data
	 * @throws IOException 
	 * */
	public void consumeResult(byte[] buffer) throws IOException;
	/**
	 * Close attached resource if needed.
	 * */
	public void closeResource() throws IOException;
	/**
	 * Close attached resource if needed.
	 * */
	@Override
	public default void close() throws IOException { closeResource(); }
	
	
	/**
	 * Consume data and writes to a <code>File</code>
	 * 
	 * @param f <code>File</code> to write the data
	 * */
	public static MessageConsumer to(File f) throws FileNotFoundException {
		return to(new FileOutputStream(f));
	}
	/**
	 * Consume data and writes to a <code>OutputStream</code>
	 * This method closes <code>OutputStream</code> after the Cipher process is finished
	 * 
	 * @see MessageConsumer#to(OutputStream, boolean)
	 * @param os <code>OutputStream</code> to write the data
	 * */
	public static MessageConsumer to(OutputStream os) {
		return to(os, true);
	}
	/**
	 * Consume data and writes to a <code>OutputStream</code>
	 * 
	 * @param os <code>OutputStream</code> to write the data
	 * @param close whether or not close <code>OutputStream</code> after the Cipher process is finished
	 * */
	public static MessageConsumer to(OutputStream os, boolean close) {
		return new MessageConsumer() {
			private OutputStream out = os;
			@Override
			public void consumeResult(byte[] buffer) throws IOException {
				try {
					out.write(buffer);
				} catch (Exception e) {
					out.close();
					throw e;
				}
			}
			@Override
			public void closeResource() throws IOException {
				if(close) out.close();
			}
		};
	}
	/**
	 * Consume data and writes to a <code>WritableByteChannel</code>
	 * This method closes <code>WritableByteChannel</code> after the Cipher process is finished
	 * 
	 * @see MessageConsumer#to(WritableByteChannel, boolean)
	 * @param ch <code>WritableByteChannel</code> to write the data
	 * */
	public static MessageConsumer to(WritableByteChannel ch) {
		return to(ch, true);
	}
	/**
	 * Consume data and writes to a <code>WritableByteChannel</code>
	 * 
	 * @param ch <code>WritableByteChannel</code> to write the data
	 * @param close whether or not close <code>WritableByteChannel</code> after the Cipher process is finished
	 * */
	public static MessageConsumer to(WritableByteChannel ch, boolean close) {
		return new MessageConsumer() {
			private WritableByteChannel out = ch;
			@Override
			public void consumeResult(byte[] buffer) throws IOException {
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer);
					while(buf.hasRemaining()) out.write(buf);
				} catch (Exception e) {
					out.close();
					throw e;
				}
			}
			@Override
			public void closeResource() throws IOException {
				if(close) out.close();
			}
		};
	}
}
