/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.cipher.symmetric;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.key.KeySize;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

/**
 * Abstract <code>CipherUtil</code> class that uses salt and iteration count for key derivation.
 * @see SymmetricKeyMaterial
 * */
public abstract class SymmetricCipherUtil extends AbstractCipherUtil {

	protected SymmetricKeyMaterial key;
	protected final SymmetricKeyMetadata keyMetadata;
	protected final KeySize keySize;

	/**
	 * Construct this {@code SymmetricCipherUtil} with given {@code CipherProperty}, {@code SymmetricKeyMetadata} and buffer size.
	 * */
	public SymmetricCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) {
		super(cipherMetadata, bufferSize);
		this.keyMetadata = keyMetadata;
		this.keySize = keySize;
		this.key = key;
	}
	


	/**
	 * Generate new {@code SecretKeySpec} for the symmetric cipher.
	 * */
	private SecretKeySpec generateKey(byte[] salt, int iterationCount) {
		return key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.size, salt, iterationCount);
	}
	

	@Override
	protected Cipher initEncrypt(MessageConsumer mc) throws NestedIOException {
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
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		return c;
	}

	@Override
	protected Cipher initDecrypt(MessageProvider mp) throws NestedIOException {
		int iterationCount = readIterationCount(mp);
		byte[] salt = readSalt(mp);
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			Cipher c = getCipherInstance();
			c.init(Cipher.DECRYPT_MODE, generateKey(salt, iterationCount));
			return c;
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}	
	}

	/**
	 * Generate random iteration count with given {@code SecureRandom} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * @return 
	 * 
	 * @see SymmetricKeyMetadata#iterationRange
	 * */
	protected int generateIterationCount(SecureRandom sr) {
		return sr.nextInt(keyMetadata.iterationRange[0], keyMetadata.iterationRange[1]);
	}


	/**
	 * Read salt from given {@code MessageProvider} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @see SymmetricKeyMetadata#saltLen
	 * */
	protected byte[] readSalt(MessageProvider mp) {
		byte[] salt = new byte[keyMetadata.saltLen]; 
		int read = 0;
		while ((read += mp.getSrc(salt, read)) != salt.length);
		return salt;
	}
	/**
	 * Read iteration count from given {@code MessageProvider} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * @return 
	 * 
	 * @see SymmetricKeyMetadata#iterationRange
	 * */
	protected int readIterationCount(MessageProvider mp) {
		byte[] iterationByte = new byte[4];
		int read = 0;
		while ((read += mp.getSrc(iterationByte, read)) != iterationByte.length);
		return ByteBuffer.wrap(iterationByte).getInt();
	}

	@Override
	protected String fields() {
		return super.fields() + ", key size : " + keySize.size + "bit, salt size : "
				+ keyMetadata.saltLen + "byte, iteration count between : " + keyMetadata.iterationRange[0] + " / " + keyMetadata.iterationRange[1];
	}
	
	
}
