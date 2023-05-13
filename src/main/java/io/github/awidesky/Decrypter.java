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

import javax.crypto.SecretKey;

public interface Decrypter {

	public void setKey(SecretKey key);
	
	public byte[] decrypt(byte[] from);
	public void decryptToFile(byte[] from, File dest);
	public String decryptToString(byte[] from);
	public String decryptToString(byte[] from, Charset encoding);
	public void decrypt(File from, File to);
	public void decrypt(InputStream from, OutputStream to);
	public void decrypt(ReadableByteChannel from, WritableByteChannel to);
	
	
}
