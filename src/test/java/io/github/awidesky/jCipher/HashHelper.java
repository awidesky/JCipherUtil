/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class HashHelper {

	public static final char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
	public static final String hashName = "SHA-512/256";
	
	public static String hashPlain(InputStream is) {
		try {
			MessageDigest digest = MessageDigest.getInstance(hashName);
			digest.reset();
			int read = 0;
			byte[] buf = new byte[8 * 1024];
			while ((read = is.read(buf)) != -1)
				digest.update(buf, 0, read);
			is.close();
			return HexFormat.of().formatHex(digest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String hashPlain(InputStream is, int i) {
		try {
			MessageDigest digest = MessageDigest.getInstance(hashName);
			int read = 0;
			int totalRead = 0;
			byte[] buf = new byte[8 * 1024];
			while ((read = is.read(buf)) != -1 && totalRead < i) {
				digest.update(buf, 0, Math.min(read, i - totalRead));
				totalRead += read;
			}
			is.close();
			return HexFormat.of().formatHex(digest.digest());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	public static String hashPlain(byte[] is) {
		try {
			MessageDigest digest = MessageDigest.getInstance(hashName);
			return HexFormat.of().formatHex(digest.digest(is));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
