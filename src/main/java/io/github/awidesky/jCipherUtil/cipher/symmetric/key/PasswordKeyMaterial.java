/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.symmetric.key;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public class PasswordKeyMaterial extends SymmetricKeyMaterial {

	private final char[] password;
	
	/**
	 * Initiate <code>PasswordKeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated because other necessary metadata(salt, iteration count) is unknown.
	 * 
	 * @param password the password. The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public PasswordKeyMaterial(char[] password) { this.password = Arrays.copyOf(password, password.length); }

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata and password.
	 * @param algorithm metadata of the Cipher. used to find key algorithm and key size.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * @throws OmittedCipherException if {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException} is thrown
	 */
	@Override
	public SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException {
	    SecretKey pbeKey;
		try {
			pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, Arrays.copyOf(salt, salt.length), iterationCount, keySize));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	    return new SecretKeySpec(pbeKey.getEncoded(), algorithm);
	}
	
}