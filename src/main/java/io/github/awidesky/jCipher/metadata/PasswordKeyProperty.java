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
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.util.NestedOmittedCipherException;

public class PasswordKeyProperty extends KeyMaterial {


	private char[] password;
	
	/**
	 * Initiate <code>PasswordKeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated because other necessary metadata(salt, iteration count) is unknown.
	 * 
	 * @param key the password. The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public PasswordKeyProperty(char[] password) { this.password = Arrays.copyOf(password, password.length); }

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata and password.
	 * @param cm metadata of the Cipher. used to find key algorithm & key size.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * 
	 * @throws NestedOmittedCipherException if {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException} is thrown
	 */
	@Override
	public SecretKeySpec genKey(CipherProperty cm, byte[] salt, int iterationCount) throws NestedOmittedCipherException {
		this.salt =  Arrays.copyOf(salt, salt.length);
		this.iterationCount = iterationCount;
	    SecretKey pbeKey;
		try {
			pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, this.salt, iterationCount, cm.KEYSIZE));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new NestedOmittedCipherException(e);
		}
	    return new SecretKeySpec(pbeKey.getEncoded(), cm.KEY_ALGORITMH_NAME);
	}
	
	
	@Override
	public void destroy() throws DestroyFailedException {
		super.destroy();
		for(int i = 0; i < password.length; i++) password[i] = '\0';
	}
}
