/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.symmetric;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;

/**
 * A superclass for symmetric {@code CipherUtil}s which use nonce or IV.
 * <p>
 * This class has various protected methods, providing default implementation for generating/writing/reading 
 * nonce and salt. Subclass may override these method, but metadata layout should not be changed.
 * <p>
 * About metadata layout, see {@link KeyMetadata}.
 * */
public abstract class SymmetricNonceCipherUtil extends SymmetricCipherUtil {

	/**
	 * Construct this {@code SymmetricCipherUtil} with given parameters.
	 * */
	protected SymmetricNonceCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) { super(keyMetadata, keySize, key, bufferSize); }

	/**
	 * Get {@code AlgorithmParameterSpec} of this cipher.
	 * default implementation returns an {@code IvParameterSpec} associated with the <code>nonce</code>.
	 * 
	 * */
	protected AlgorithmParameterSpec getAlgorithmParameterSpec(byte[] nonce) {
		return new IvParameterSpec(nonce);
	}
	
	/**
	 * Generate random nonce with given {@code SecureRandom} instance.
	 * Size of the nonce is determined by {@code CipherProperty}.
	 * 
	 * @return generated nonce
	 * @see IVCipherProperty#NONCESIZE
	 * */
	protected byte[] generateNonce(SecureRandom sr) {
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		sr.nextBytes(nonce);
		return nonce;
	}
	
	/**
	 * @return <code>IVCipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	public abstract IVCipherProperty getCipherProperty();


	/**
	 * Generates random iteration count, salt, and nonce, and initiate the <code>Cipher</code> instance.
	 * Generated metadata will written to the parameter.
	 * This method can be override to generate and write additional metadata(like Initial Vector).
	 * 
	 * @param metadata a pre-allocated byte array. The generated metadata will be written to it.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * */
	@Override
	protected Cipher initEncrypt(byte[] metadata) {
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
		int iterationCount = generateIterationCount(sr);
		byte[] nonce = generateNonce(sr);
		Cipher c = getCipherInstance();
		initCipherInstance(c, Cipher.ENCRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		ByteBuffer met = ByteBuffer.wrap(metadata);
		met.putInt(iterationCount);
		met.put(salt);
		met.put(nonce);
		return c;
	}

	/**
	 * Reads iteration count, salt, and nonce from the given metadata, and initiate the <code>Cipher</code> instance.
	 * This method can be override to read additional metadata(like initial vector).
	 *
	 * @param metadata a {@code ByteBuffer} that contains metadata.
	 * 		  Size is defined in {@code AbstractCipherUtil#getMetadataLength()}.
	 * @return initiated {@code Cipher} instance
	 * */
	@Override
	protected Cipher initDecrypt(ByteBuffer metadata) {
		byte[] salt = new byte[keyMetadata.saltLen];
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		int iterationCount = metadata.clear().getInt();
		metadata.get(salt);
		metadata.get(nonce);

		if (!(keyMetadata.iterationRangeStart <= iterationCount && iterationCount < keyMetadata.iterationRangeEnd)) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRangeStart + " and " + keyMetadata.iterationRangeEnd);
		}
		Cipher c = getCipherInstance();
		initCipherInstance(c, Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		return c;
	}
	
	@Override
	protected int getMetadataLength() {
		return ITERATION_COUNT_SIZE + keyMetadata.saltLen + getCipherProperty().NONCESIZE;
	}
	
	/**
	 * @return String represents this CipherUtil instance. <code>super.fields()</code> will be followed by value of the nonce.
	 * */
	@Override
	protected String fields() {
		return super.fields() + ", Nonce Size : " + getCipherProperty().NONCESIZE + "byte";
	}

}
