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
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;

/**
 * A password key material generates key with given password.
 * Length of the password is irrelevant from generated key value, but since it's the only secret data used in key generation,
 * it is recommended to use long password.
 * <p>
 * The given password is not used directly as a secret key; it's salted and hashed multiple times via {@code PBKDF2WithHmacSHA512} algorithm.
 * Every data except for the password is non-secret({@code salt}, {@code iteration count}) data, and received via parameters of 
 * {@code PasswordKeyMaterial#genKey(String, int, byte[], int)} method.
 * */
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
	 * @param algorithm metadata of the Cipher. used to find key algorithm and key value.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * 
	 * @throws OmittedCipherException if {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException} is thrown
	 * @throws IllegalStateException if this object is destroyed
	 */
	@Override
	public SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException, IllegalStateException{
	    if(destroyed) throw new IllegalStateException("The key material is destroyed!");
		SecretKey pbeKey;
		try { //maybe PBEKeySpec.clearPassword must be called
			pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, Arrays.copyOf(salt, salt.length), iterationCount, keySize));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
		byte[] key = pbeKey.getEncoded();
		SecretKeySpec ret = new SecretKeySpec(key, algorithm);
		clearArray(key);
		return ret;
	}

	@Override
	public void destroy() {
		Random r = new Random();
		for(int i = 0; i < password.length; i++) {
			password[i] = (char)r.nextInt();
		}
		destroyed = true;
	}
	
}
