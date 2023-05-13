/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;

public interface Encrypter {

	public byte[] encrypt(byte[] from);
	public byte[] encrypt(File from);
	public byte[] encrypt(String from);
	public byte[] encrypt(String from, Charset encoding);
	public void encrypt(File from, File to);
	public void encrypt(InputStream from, OutputStream to);
	public void encrypt(ReadableByteChannel from, WritableByteChannel to);
	
}
