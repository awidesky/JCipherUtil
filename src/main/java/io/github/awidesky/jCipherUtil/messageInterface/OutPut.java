/*	
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.messageInterface;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;


/**
 * An Interface that abstracts consuming data and sending it to various destinations(e.g. a file, an <code>OutputStream</code> etc.).
 * <p>This interface does not care if the data is encrypted or not. It only generates thin abstraction among various source types.
 * */
public interface OutPut extends AutoCloseable {

	/**
	 * Writes the data(may be a plainText or cipherText) to the destination(may be a <code>String</code>, <code>File</code>, <code>OutPutStream</code> etc.)
	 * 
	 * @param buffer the data
	 * @throws NestedIOException 
	 * */
	public void consumeResult(byte[] buffer) throws NestedIOException;
	/**
	 * Close attached resource if needed.
	 * <p>This method just calls {@code OutPut#closeResource()}
	 * */
	@Override
	public void close() throws NestedIOException;
	
	
	/**
	 * Returns a {@code OutPut} that writes data to given <code>File</code>
	 * 
	 * @param f <code>File</code> to write the data
	 * */
	public static OutPut to(File f) throws FileNotFoundException {
		return to(new FileOutputStream(f));
	}
	/**
	 * Returns a {@code OutPut} that writes data to given <code>Path</code>
	 * 
	 * @param p the destination
	 * @throws IOException if an I/O error occurs
	 * */
	public static OutPut to(Path p) throws IOException {
		return to(FileChannel.open(p, StandardOpenOption.WRITE));
	}
	/**
	 * Returns a {@code OutPut} that writes data to given <code>OutputStream</code>.<p>
	 * This method closes <code>OutputStream</code> after the Cipher process is finished
	 * 
	 * @see OutPut#to(OutputStream, boolean)
	 * @param os <code>OutputStream</code> to write the data
	 * */
	public static OutPut to(OutputStream os) {
		return to(os, true);
	}
	/**
	 * Returns a {@code OutPut} that writes data to given <code>OutputStream</code>
	 * 
	 * @param os <code>OutputStream</code> to write the data
	 * @param close whether close <code>OutputStream</code> after the Cipher process is finished
	 * */
	public static OutPut to(OutputStream os, boolean close) {
		return new OutPut() {
			private OutputStream out = os;
			@Override
			public void consumeResult(byte[] buffer) throws NestedIOException {
				try {
					out.write(buffer);
				} catch (IOException e) {
					close();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void close() throws NestedIOException {
				try { if(close) out.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
	/**
	 * Returns a {@code OutPut} that writes data to given <code>WritableByteChannel</code>
	 * This method closes <code>WritableByteChannel</code> after the Cipher process is finished
	 * 
	 * @see OutPut#to(WritableByteChannel, boolean)
	 * @param ch <code>WritableByteChannel</code> to write the data
	 * */
	public static OutPut to(WritableByteChannel ch) {
		return to(ch, true);
	}
	/**
	 * Returns a {@code OutPut} that writes data to given <code>WritableByteChannel</code>
	 * 
	 * @param ch <code>WritableByteChannel</code> to write the data
	 * @param close whether close <code>WritableByteChannel</code> after the Cipher process is finished
	 * */
	public static OutPut to(WritableByteChannel ch, boolean close) {
		return new OutPut() {
			private WritableByteChannel out = ch;
			@Override
			public void consumeResult(byte[] buffer) throws NestedIOException {
				try {
					ByteBuffer buf = ByteBuffer.wrap(buffer);
					while(buf.hasRemaining()) out.write(buf);
				} catch (IOException e) {
					close();
					throw new NestedIOException(e);
				}
			}
			@Override
			public void close() throws NestedIOException {
				try { if(close) out.close(); }
				catch (IOException e) { throw new NestedIOException(e);	}
			}
		};
	}
}
