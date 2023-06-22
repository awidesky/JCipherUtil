/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.metadata.key;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class KeyMaterial {

	protected byte[] salt;
	protected int iterationCount;
	
	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * @param algorithm key algorithm.
	 * @param keySize size of key in bits.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * @throws OmittedCipherException if an {@link RuntimeException}(like {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException}) is thrown
	 */
	public abstract SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException;
	
	/**
	 * @return Salt value for the password-based key generation algorithm.
	 * The contents of the result were copied to protect against subsequent modification.
	 * */
	public byte[] getSalt() { return Arrays.copyOf(salt, salt.length); }
	/**
	 * @return Iteration count for the password-based key generation algorithm
	 * */
	public int getIterationCount() { return iterationCount; }
	
	/**
	 * Destroy the <code>SecretKeySpec</code>, password and metadata
	 * */
	public void destroy() throws DestroyFailedException {
		//key.destroy(); only KerberosKey implement destroy method.
		//https://stackoverflow.com/questions/38276866/destroying-secretkey-throws-destroyfailedexception
		for(int i = 0; i < salt.length; i++) salt[i] = (byte)0;
		iterationCount = -1;
	}

}