/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.metadata.key;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.util.OmittedCipherException;

public class ByteArrayKeyMaterial extends KeyMaterial {

	private byte[] key;
	
	/**
	 * Initiate <code>KeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated because other necessary metadata(salt, iteration count) is unknown.
	 * <p>The <code>key</code> is stretched via <code>SHA-512</code> algorithm.
	 * <p>This process is needed for consistency of key generating algorithm & metadata layout. 
	 * Since password salt and iteration count is included in cipherText header metadata,
	 * they should be used in every cases, otherwise, metadata scheme should be more complicated to let 
	 * cipher processor know if the cipherText uses salt&iteration count or not.
	 * And if <code>key</code> as byte array isn't salted, user might use same byte array multiple times,
	 * which causes vulnerability.
	 * 
	 * @param key the key
	 * The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public ByteArrayKeyMaterial(byte[] key) { this.key = Arrays.copyOf(key, key.length); }

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * @param algorithm metadata of the Cipher. used to find key algorithm & key size.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * @throws OmittedCipherException if {@link NoSuchAlgorithmException} is thrown
	 */
	@Override
	public SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException {
		this.salt =  Arrays.copyOf(salt, salt.length);
		this.iterationCount = iterationCount;
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
		byte[] result = key;
		
		for (int i = 0; i < iterationCount; i++) { //key stretching
			digest.reset();
			digest.update(result);
			digest.update(salt);
			result = digest.digest();
		}

		return new SecretKeySpec(result, 0, keySize / 8, algorithm);
	}
	
	@Override
	public void destroy() throws DestroyFailedException {
		super.destroy();
		for(int i = 0; i < key.length; i++) key[i] = 0;
	}
}
