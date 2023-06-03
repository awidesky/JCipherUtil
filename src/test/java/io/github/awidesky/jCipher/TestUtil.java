/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import io.github.awidesky.jCipher.aes.AESGCMCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

public class TestUtil {

	public static char[] password = "tH!s1Smyp@Ssw0rd".toCharArray();
	
	public static String hashPlain(InputStream is) throws NoSuchAlgorithmException, IOException, DigestException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		int read = 0;
		byte[] buf = new byte[8 * 1024];
		while((read = is.read(buf)) != -1) digest.update(buf, 0, read);
		is.close();
		return HexFormat.of().formatHex(digest.digest());
	}
	public static String hashPlain(InputStream is, int i) throws NoSuchAlgorithmException, DigestException, IOException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		int read = 0;
		int totalRead = 0;
		byte[] buf = new byte[8 * 1024];
		while((read = is.read(buf)) != -1 && totalRead < i) {
			digest.update(buf, 0, Math.min(read, i - totalRead));
			totalRead += read;
		}
		is.close();
		return HexFormat.of().formatHex(digest.digest());
	}
	public static String hashPlain(byte[] is) throws NoSuchAlgorithmException, IOException, DigestException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		return HexFormat.of().formatHex(digest.digest(is));
	}
	public static String testDecrypt(InputStream is) throws DigestException, IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		return HexFormat.of().formatHex(digest.digest(new AESGCMCipherUtil(8 * 1024).init(password).decryptToSingleBuffer(MessageProvider.from(is))));
	}
	public static String testEncrypt(InputStream is) throws DigestException, IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		return HexFormat.of().formatHex(digest.digest(new AESGCMCipherUtil(8 * 1024).init(password).encryptToSingleBuffer(MessageProvider.from(is))));
	}
}