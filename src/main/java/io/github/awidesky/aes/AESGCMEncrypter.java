/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.aes;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import io.github.awidesky.Encrypter;

public class AESGCMEncrypter implements Encrypter {

	private SecretKey key; //TODO : how to get a key?

	@Override
	public byte[] encrypt(byte[] from) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] encrypt(File from) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] encrypt(String from) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] encrypt(String from, Charset encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void encrypt(File from, File to) {
		// TODO Auto-generated method stub

	}

	@Override
	public void encrypt(InputStream from, OutputStream to) {
		// TODO Auto-generated method stub

	}

	@Override
	public void encrypt(ReadableByteChannel from, WritableByteChannel to) {
		// TODO Auto-generated method stub

	}


}
