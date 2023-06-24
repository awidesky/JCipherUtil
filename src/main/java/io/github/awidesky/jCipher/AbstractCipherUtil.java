/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.DestroyFailedException;

import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.CipherProperty;
import io.github.awidesky.jCipher.metadata.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipher.metadata.key.KeyMaterial;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;
import io.github.awidesky.jCipher.metadata.key.PasswordKeyMaterial;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

/**
 * Abstract <code>CipherUtil</code> class that uses salt and iteration count for key derivation.
 * @see KeyMaterial
 * */
public abstract class AbstractCipherUtil implements CipherUtil {

	protected KeyMaterial key;
	protected KeyMetadata keyMetadata;
	protected byte[] salt;
	protected int iterationCount;
	protected Cipher cipher;
	protected final int BUFFER_SIZE;
	protected CipherProperty cipherMetadata;
	
	protected AbstractCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata) {
		this(cipherMetadata, keyMetadata, 8 * 1024);
	}
	protected AbstractCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, int bufferSize) {
		this.cipherMetadata = cipherMetadata;
		this.keyMetadata = keyMetadata;
		this.BUFFER_SIZE = bufferSize;
		try {
			cipher = Cipher.getInstance(getCipherMetadata().ALGORITMH_NAME + "/" + getCipherMetadata().ALGORITMH_MODE + "/" + getCipherMetadata().ALGORITMH_PADDING);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * @return <code>CipherProperty</code> of this <code>CipherUtil</code>
	 * */
	protected abstract CipherProperty getCipherMetadata();

	/**
	 * Initialize <code>Cipher</code> in encrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * 
	 * This method should do tasks like reading metadata.. etc.  
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract void initEncrypt(MessageConsumer mc) throws NestedIOException;
	/**
	 * Initialize <code>Cipher</code> in decrypt mode so that it can be usable(be able to call <code>cipher.update</code>, <code>cipher.doFinal</code>
	 * 
	 * This method should do tasks like reading metadata.. etc.  
	 * @throws NestedIOException if {@code IOException} is thrown.
	 * */
	protected abstract void initDecrypt(MessageProvider mp) throws NestedIOException;

	/**
	 * Generate random salt with given {@code SecureRandom} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @see KeyMetadata#saltLen
	 * */
	protected void generateSalt(SecureRandom sr) {
		salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
	}
	/**
	 * Generate random iteration count with given {@code SecureRandom} instance.
	 * Size of the iteration count is determined by {@code KeyMetadata}.
	 * 
	 * @see KeyMetadata#iterationRange
	 * */
	protected void generateIterationCount(SecureRandom sr) {
		iterationCount = sr.nextInt(keyMetadata.iterationRange[0], keyMetadata.iterationRange[1]);
	}
	/**
	 * Read salt from given {@code MessageProvider} instance.
	 * Size of the salt is determined by {@code KeyMetadata}.
	 * 
	 * @see KeyMetadata#saltLen
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
	 * @see KeyMetadata#iterationRange
	 * */
	protected void readIterationCount(MessageProvider mp) {
		byte[] iterationByte = new byte[4];
		int read = 0;
		while ((read += mp.getSrc(iterationByte, read)) != iterationByte.length);
		iterationCount = ByteBuffer.wrap(iterationByte).getInt();
	}

	/**
	 * @return The salt for the key
	 * */
	public byte[] getSalt() { return key.getSalt(); }
	
	/**
	 * Initialize <code>Cipher</code> with given password
	 *
	 * @param password the password
	 * */
	@Override
	public CipherUtil init(char[] password) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new PasswordKeyMaterial(password);
		return this;
	}
	/**
	 * Initialize <code>Cipher</code> with given key.
	 * <p><i><b>The argument byte array is directly used as <code>SecretKey</code>(after key stretching)</b></i>
	 * 
	 * @see KeyMaterial#KeyProperty(byte[])
	 * 
	 * @param key the key
	 * */
	@Override
	public CipherUtil init(byte[] key) {
		try {
			if(this.key != null) this.key.destroy();
		} catch (DestroyFailedException e) { throw new OmittedCipherException(e); }
		this.key = new ByteArrayKeyMaterial(key);
		return this;
	}


	
	/**
	 * Encrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link AbstractCipherUtil#initEncrypt(MessageConsumer)},
	 * {@link AbstractCipherUtil#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see AbstractCipherUtil#initEncrypt(MessageConsumer)
	 * @see AbstractCipherUtil#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void encrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			initEncrypt(mc);
			processCipher(mp, mc);
		}
	}

	/**
	 * Decrypt from source(designated as <code>MessageProvider</code>)
	 * and writes to given destination(designated as <code>MessageConsumer</code>).
	 * <p>Default implementation calls two method {@link AbstractCipherUtil#initDecrypt(MessageProvider)},
	 * {@link AbstractCipherUtil#processCipher(MessageProvider, MessageConsumer)}, and close both parameters.
	 *
	 * @see AbstractCipherUtil#initEncrypt(MessageConsumer)
	 * @see AbstractCipherUtil#processCipher(MessageProvider, MessageConsumer)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc Data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	@Override
	public void decrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		try (mp; mc) {
			initDecrypt(mp);
			processCipher(mp, mc);
		}
	}
	
	/**
	 * Do Cipher Process with pre-initiated <code>cipher</code>.
	 * 
	 * @param mp Plain data Provider of source for encryption/decryption
	 * @param mc Data Consumer that writes encrypted/decryption data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	protected void processCipher(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException {
		byte[] buf = new byte[BUFFER_SIZE];
		while(true) {
			int read = mp.getSrc(buf);
			if(read == -1) break;
			byte[] result = cipher.update(buf, 0, read);
			if(result != null) mc.consumeResult(result);
		}
		try {
			mc.consumeResult(cipher.doFinal());
		} catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + cipher.getAlgorithm() + " from " + cipher.getProvider() + ", Nonce Size : " + getCipherMetadata().NONCESIZE
				+ "byte, key size : " + keyMetadata.keyLen + "bit, salt size : " + keyMetadata.saltLen + "byte, iteration count between : "
				+ keyMetadata.iterationRange[0] + " / " + keyMetadata.iterationRange[1] + "]";
	}
}
