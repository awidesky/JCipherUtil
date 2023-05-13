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

public class UpdatableDecrypter implements Decrypter {

	@Override
	public void setKey(SecretKey key) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] decrypt(byte[] from) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void decryptToFile(byte[] from, File dest) {
		// TODO Auto-generated method stub

	}

	@Override
	public String decryptToString(byte[] from) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String decryptToString(byte[] from, Charset encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void decrypt(File from, File to) {
		// TODO Auto-generated method stub

	}

	@Override
	public void decrypt(InputStream from, OutputStream to) {
		// TODO Auto-generated method stub

	}

	@Override
	public void decrypt(ReadableByteChannel from, WritableByteChannel to) {
		// TODO Auto-generated method stub

	}

}
