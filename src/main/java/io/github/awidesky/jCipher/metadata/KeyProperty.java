/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.metadata;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

public class KeyProperty {

	private SecretKeySpec key;
	private char[] password;
	private byte[] salt;
	int iterationCount;
	
	public KeyProperty(byte[] key) { this.password = byteArrToCharArr(key); }
	public KeyProperty(char[] key) { this.password = key; }
	
	
	public SecretKeySpec genKey(CipherProperty cm, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException {
		this.salt = salt;
		this.iterationCount = iterationCount;
	    SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, salt, iterationCount, cm.KEYSIZE));
	    return (key = new SecretKeySpec(pbeKey.getEncoded(), cm.KEY_ALGORITMH_NAME));
	}
	
	public SecretKeySpec getKey() { return key; }
	public byte[] getSalt() { return salt; }
	public int getIterationCount() { return iterationCount; }
	
	public void destroy() throws DestroyFailedException {
		SecureRandom sr = new SecureRandom();
		key.destroy();
		for(int i = 0; i < password.length; i++) password[i] = (char)sr.nextInt();
		for(int i = 0; i < salt.length; i++) salt[i] = (byte)sr.nextInt();
		iterationCount = sr.nextInt();
	}

	private static char[] byteArrToCharArr(byte[] password) {
    	char[] ret = new char[password.length * 2];
    	for(int i = 0; i < password.length; i++) {
    		ret[i * 2] = HexFormat.of().toHighHexDigit(password[i]);
    		ret[i * 2 + 1] = HexFormat.of().toLowHexDigit(password[i]);
    	}
		return ret;
	}
}
