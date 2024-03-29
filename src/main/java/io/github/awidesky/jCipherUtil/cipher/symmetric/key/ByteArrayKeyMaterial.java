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
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.hash.Hash;
import io.github.awidesky.jCipherUtil.hash.Hashes;

/**
 * A byte array key material generates key with given byte array.
 * Length of the array is irrelevant from generated key value, but since it's the only secret data used in key generation,
 * it is recommended to use long data.
 * <p>
 * The given byte array is not used directly as a secret key; it's salted and hashed multiple({@code iteration count}) times.
 * Every data except for the byte array is non-secret({@code salt}, {@code iteration count}) data, and received via parameters of 
 * {@code ByteArrayKeyMaterial#genKey(String, int, byte[], int)} method.
 * */
public class ByteArrayKeyMaterial extends SymmetricKeyMaterial {

	private final byte[] key;
	private final Hashes hash;
	
	/**
	 * Initiate <code>KeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated now, because other necessary metadata(salt, iteration count) is unknown.
	 * <p>The <code>key</code> is stretched via default <code>SHA3-512</code> algorithm.
	 * <p>This process is needed for consistency of key generating algorithm and metadata layout. 
	 * Since password salt and iteration count is included in cipherText header metadata,
	 * they should be used in every cases, otherwise, metadata scheme should be more complicated to let 
	 * cipher processor know if the cipherText uses salt and iteration count or not.
	 * And if <code>key</code> as byte array isn't salted, user might use same byte array multiple times,
	 * which causes vulnerability.
	 * 
	 * @param key the key
	 * The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public ByteArrayKeyMaterial(byte[] key) { this(key, Hashes.SHA3_512); }
	/**
	 * Initiate <code>KeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated now, because other necessary metadata(salt, iteration count) is unknown.
	 * <p>The <code>key</code> is stretched via given hash algorithm.
	 * <p>This process is needed for consistency of key generating algorithm and metadata layout. 
	 * Since password salt and iteration count is included in cipherText header metadata,
	 * they should be used in every cases, otherwise, metadata scheme should be more complicated to let 
	 * cipher processor know if the cipherText uses salt and iteration count or not.
	 * And if <code>key</code> as byte array isn't salted, user might use same byte array multiple times,
	 * which causes vulnerability.
	 * 
	 * @param key the key
	 * @param hash the hash algorithm used for key stretching
	 * The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public ByteArrayKeyMaterial(byte[] key, Hashes hash) {
		this.key = Arrays.copyOf(key, key.length);
		this.hash = hash;
	}

	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * 
	 * @param algorithm metadata of the Cipher. used to find key algorithm and key value.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * 
	 * @throws OmittedCipherException if {@link NoSuchAlgorithmException} is thrown
	 * @throws IllegalStateException if this object is destroyed
	 */
	@Override
	public SecretKeySpec genKey(String algorithm, int keySize, byte[] salt, int iterationCount) throws OmittedCipherException, IllegalStateException {
		if(destroyed) throw new IllegalStateException("The key material is destroyed!");
		Hash digest = hash.getInstance();
		byte[] result = key;
		
		for (int i = 0; i < iterationCount; i++) { //key stretching
			digest.reset();
			digest.update(result);
			digest.update(Arrays.copyOf(salt, salt.length));
			result = digest.doFinalToBytes();
		}
		while(result.length < keySize) {
			digest.reset();
			byte[] hashed = digest.doFinalToBytes(result);
	        byte[] result1 = new byte[result.length + hashed.length];
	        System.arraycopy(result, 0, result1, 0, result.length);
	        System.arraycopy(hashed, 0, result1, result.length, hashed.length);
	        clearArray(result); clearArray(hashed);
	        result = result1;
		}
		SecretKeySpec ret = new SecretKeySpec(result, 0, keySize / 8, algorithm);
		clearArray(result);
		return ret;
	}
	
	/***
	 * Returns a copy of the key source data.
	 * @return a copy of the key source data.
	 */
	public byte[] getKeySource() {
		return Arrays.copyOf(key, key.length);
	}

	@Override
	public void destroy() {
		clearArray(key);
		destroyed = true;
	}
	
}
