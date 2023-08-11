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

import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public abstract class SymmetricKeyMaterial {

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * @param algorithm key algorithm.
	 * @param keySize size of key in bits.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * @throws OmittedCipherException if an {@link RuntimeException}(like {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException}) is thrown
	 */
	public abstract SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException;
	

}