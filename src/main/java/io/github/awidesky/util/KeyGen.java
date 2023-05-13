/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.util;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyGen {
	
	public static Key getRandomKey(String cipher, int keySize) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher);
	    keyGenerator.init(keySize);
	    return keyGenerator.generateKey();
	}
	
	public static Key getPasswordBasedKey(String cipher, char[] password, int keySize, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException {
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount, keySize);
	    SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(pbeKeySpec);
	    return new SecretKeySpec(pbeKey.getEncoded(), cipher);
	}
	
	public static Key getKey(String cipher, byte[] password) {
		return new SecretKeySpec(password, cipher);
	}
	
}
