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
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.AbstractCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMaterial;
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
	protected SymmetricKeyMetadata keyMetadata;
	protected byte[] salt;
	protected int iterationCount;

	/**
	 * Construct this {@code SymmetricCipherUtil} with given {@code CipherProperty}, {@code SymmetricKeyMetadata} and default buffer size.
	 * */
	public SymmetricCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata) {
		super(cipherMetadata);
		this.keyMetadata = keyMetadata;
	}
	/**
	 * Construct this {@code SymmetricCipherUtil} with given {@code CipherProperty}, {@code SymmetricKeyMetadata} and buffer size.
	 * */
	public SymmetricCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, int bufferSize) {
		super(cipherMetadata, bufferSize);
		this.keyMetadata = keyMetadata;
	}
	
	/**
	 * Generate new {@code Key} for encryption. Encryption and decryption is done by the same key.
	 * */
	@Override
	protected Key getEncryptKey() { return generateKey(); }
	/**
	 * Generate new {@code Key} for decryption. Encryption and decryption is done by the same key.
	 * */
	@Override
	protected Key getDecryptKey() { return generateKey(); }


	/**
	 * Generate new {@code SecretKeySpec} for the symmetric cipher.
	 * */
	private SecretKeySpec generateKey() { //TODO : do not regenerate key if it's already generated!
		return key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount);
	}
	
	/**
	 * @return The salt for the key
	 * */
	public byte[] getSalt() { return key.getSalt(); }
	
	/**
	 * Initialize <code>AbstractSymmetricCipherUtil</code> with given password
	 *
	 * @param password the password
	 * */
	public SymmetricCipherUtil init(char[] password) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new PasswordKeyMaterial(password);
		return this;
	}
	/**
	 * Initialize <code>AbstractSymmetricCipherUtil</code> with given <code>byte[]</code> key.
	 * <p><i><b>The argument byte array is directly used as <code>SecretKey</code>(after key stretching)</b></i>
	 * 
	 * @see ByteArrayKeyMaterial#ByteArrayKeyMaterial(byte[])
	 * 
	 * @param key the key
	 * */
	public SymmetricCipherUtil init(byte[] key) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new ByteArrayKeyMaterial(key);
		return this;
	}
	
	

	@Override
	protected Cipher initEncrypt(MessageConsumer mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		generateSalt(sr);
		generateIterationCount(sr);
		Cipher c = super.initEncrypt(mc);
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		return c;
	}

	@Override
	protected Cipher initDecrypt(MessageProvider mp) throws NestedIOException {
		readIterationCount(mp);
		readSalt(mp);
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		return super.initDecrypt(mp);
	}

	/**
	 * Generate random salt with given {@code SecureRandom} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @see SymmetricKeyMetadata#saltLen
	 * */
	protected void generateSalt(SecureRandom sr) {
		salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
	}
	/**
	 * Generate random iteration count with given {@code SecureRandom} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @see SymmetricKeyMetadata#iterationRange
	 * */
	protected void generateIterationCount(SecureRandom sr) {
		iterationCount = sr.nextInt(keyMetadata.iterationRange[0], keyMetadata.iterationRange[1]);
	}


	/**
	 * Read salt from given {@code MessageProvider} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @see SymmetricKeyMetadata#saltLen
	 * */
	protected void readSalt(MessageProvider mp) {
		salt = new byte[keyMetadata.saltLen]; 
		int read = 0;
		while ((read += mp.getSrc(salt, read)) != salt.length);
	}
	/**
	 * Read iteration count from given {@code MessageProvider} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @see SymmetricKeyMetadata#iterationRange
	 * */
	protected void readIterationCount(MessageProvider mp) {
		byte[] iterationByte = new byte[4];
		int read = 0;
		while ((read += mp.getSrc(iterationByte, read)) != iterationByte.length);
		iterationCount = ByteBuffer.wrap(iterationByte).getInt();
	}

	@Override
	protected String fields() {
		return super.fields() + ", key size : " + keyMetadata.keyLen + "bit, salt size : "
				+ keyMetadata.saltLen + "byte, iteration count between : " + keyMetadata.iterationRange[0] + " / " + keyMetadata.iterationRange[1];
	}
	
	
}
