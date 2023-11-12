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
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipherUtil.AbstractCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;

/**
 * Base class of all CipherUtil that uses symmetric cipher algorithm and salt, iteration count.
 * <p>
 * This class has a set of protected/private method implementations for common behavior among symmetric cipherUtil classes.
 * That includes initiating encryption/decryption, generating/reading salt/iteration count.
 * <p>
 * Necessary parameters for symmetric cipher are salt and iteration count.
 * In encryption mode, random salt of given value and random iteration count between given range is generated.
 * Those values are stored very first of the output. Iteration count is stored in first to prevent reading illegal value
 * (unlike salt, abnormal value of iteration count can lead to various fatal problems. See {@link KeyMetadata}).
 * The length of the salt is not saved; it must be known in advance.
 * <p>
 * In decryption mode, first 4 bytes are read and interpreted to a {@code int} as big endian.
 * If the value is not in the range specified in {@code KeyMetadata}, {@code IllegalMetadataException} is thrown.
 * After that, salt is read(Length of the salt must provided via {@code KeyMetadata}).
 * The program cannot tell if salt length specified in {@code KeyMetadata} is differ from that used in encryption.
 * If value of the salt is abnormal, decryption process will fail or produce wrong plaintext.
 * <p>
 * Every subclass of {@code SymmetricCipherUtil} follows same metadata structure - first 4 bytes(in big endian) are iteration count, then salt.
 * Additional metadata may be followed if a subclass overrides(for example, {@link SymmetricNonceCipherUtil}).
 * 
 * @see SymmetricKeyMaterial
 * @see KeyMetadata
 * */
public abstract class SymmetricCipherUtil extends AbstractCipherUtil {

	protected SymmetricKeyMaterial key;
	protected final KeyMetadata keyMetadata;
	protected final KeySize keySize;
	
	protected final int ITERATION_COUNT_SIZE = 4; /* One int value */

	/**
	 * Construct this {@code SymmetricCipherUtil} with given parameters.
	 * */
	protected SymmetricCipherUtil(KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(bufferSize);
		this.keyMetadata = keyMetadata;
		this.keySize = keySize;
		this.key = key;
	}
	


	/**
	 * Generate new {@code SecretKeySpec} for the symmetric cipher.
	 * */
	private SecretKeySpec generateKey(byte[] salt, int iterationCount) {
		return key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount);
	}
	

	/**
	 * Generates random salt and iteration count, initiate the <code>Cipher</code> instance, and write iteration count and salt
	 * to {@code OutPut}.
	 * This method can be override to generate and write additional metadata(like Initial Vector).
	 * */
	@Override
	protected Cipher initEncrypt(OutPut out) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
		int iterationCount = generateIterationCount(sr);
		Cipher c = null;
		try {
			c = getCipherInstance();
			c.init(Cipher.ENCRYPT_MODE, generateKey(salt, iterationCount));
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
		out.consumeResult(ByteBuffer.allocate(ITERATION_COUNT_SIZE).putInt(iterationCount).array());
		out.consumeResult(salt);
		return c;
	}
	

	protected Cipher initEncrypt(byte[] metadata) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
		int iterationCount = generateIterationCount(sr);
		Cipher c = getCipherInstance();
		try {
			c.init(Cipher.ENCRYPT_MODE, generateKey(salt, iterationCount));
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
		byte[] iter = ByteBuffer.allocate(ITERATION_COUNT_SIZE).putInt(iterationCount).array();
		System.arraycopy(iter, 0, metadata, 0, iter.length);
		System.arraycopy(salt, 0, metadata, iter.length, salt.length);
		return c;
	}

	/**
	 * Reads iteration count and salt from {@code InPut}, and initiate the <code>Cipher</code> instance.
	 * This method can be override to read additional metadata(like Initial Vector) from {@code OutPut} 
	 * */
	@Override
	protected Cipher initDecrypt(InPut in) throws NestedIOException {
		int iterationCount = readIterationCount(in);
		byte[] salt = readSalt(in);
		if (!(keyMetadata.iterationRangeStart <= iterationCount && iterationCount < keyMetadata.iterationRangeEnd)) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRangeStart + " and " + keyMetadata.iterationRangeEnd);
		}
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, generateKey(salt, iterationCount));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}
	protected Cipher initDecrypt(byte[] metadata) throws NestedIOException {
		ByteBuffer met = ByteBuffer.wrap(metadata);
		int iterationCount = met.getInt();
		byte[] salt = new byte[keyMetadata.saltLen];
		met.get(salt);
		if (!(keyMetadata.iterationRangeStart <= iterationCount && iterationCount < keyMetadata.iterationRangeEnd)) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRangeStart + " and " + keyMetadata.iterationRangeEnd);
		}
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, generateKey(salt, iterationCount));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	protected int getMetadataLength() {
		return ITERATION_COUNT_SIZE + keyMetadata.saltLen;
	}

	/**
	 * Generate random iteration count with given {@code SecureRandom} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @return randomly decided number of iteration count
	 * */
	protected int generateIterationCount(SecureRandom sr) {
		return sr.nextInt(keyMetadata.iterationRangeStart, keyMetadata.iterationRangeEnd);
	}


	/**
	 * Read salt from given {@code InPut} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @return salt data read from the input
	 * @see KeyMetadata#saltLen
	 * */
	protected byte[] readSalt(InPut in) {
		byte[] salt = new byte[keyMetadata.saltLen]; 
		int read = 0;
		while ((read += in.getSrc(salt, read)) != salt.length);
		return salt;
	}
	/**
	 * Read iteration count from given {@code InPut} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @return interpreted number of iteration count
	 * */
	protected int readIterationCount(InPut in) {
		byte[] iterationByte = new byte[4];
		int read = 0;
		while ((read += in.getSrc(iterationByte, read)) != iterationByte.length);
		return ByteBuffer.wrap(iterationByte).getInt();
	}
	
	/**
	 * Returns the size of the key
	 * @return the size of the key
	 */
	public int keySize() {
		return keySize.value;
	}

	/**
	 * @return String represents this CipherUtil instance. <code>super.fields()</code> will be followed by value of the key and salt, iteration count range.
	 * */
	@Override
	protected String fields() {
		return super.fields() + ", key value : " + keySize.value + "bit, salt value : "
				+ keyMetadata.saltLen + "byte, iteration count : [" + keyMetadata.iterationRangeStart + ", " + keyMetadata.iterationRangeEnd + ")";
	}
	
	@Override
	public void destroyKey() {
		key.destroy();
	}
	
}
