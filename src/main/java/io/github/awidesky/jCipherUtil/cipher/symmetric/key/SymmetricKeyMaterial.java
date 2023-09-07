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

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;

/**
 * A {@code SymmetricKeyMaterial} is a symmetric key <i>material</i> - a mandatory secret data used in
 * generating secret keys. It only holds <b>secret</b> data used for the key generation, not salt, key value, or 
 * iteration count for key deriving. Additionally, value of the secret data that {@code SymmetricKeyMaterial} holds is irrelevant to value of generated {@code SecretKey}.
 * <p>
 * One {@code SymmetricKeyMaterial} object will be able to generate {@code SecretKeySpec} of any given symmetric cipher algorithm and key value(permitted by the cipher algorithm).  
 * Also, one {@code SymmetricKeyMaterial} object will produce same {@code SecretKeySpec} in {@code SymmetricKeyMaterial#genKey(String, int, byte[], int)}
 * call if additional parameters(cipher algorithm, key value, salt, iteration count) are all the same.
 * */
public abstract class SymmetricKeyMaterial {

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * 
	 * @param algorithm key algorithm.
	 * @param keySize value of key in bits.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * 
	 * @throws OmittedCipherException if an {@link RuntimeException}(like {@link NoSuchAlgorithmException} or {@link InvalidKeySpecException}) is thrown
	 */
	public abstract SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException;
	

}