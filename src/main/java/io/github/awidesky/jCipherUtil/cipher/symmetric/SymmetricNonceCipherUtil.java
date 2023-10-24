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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.SymmetricKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
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
	protected byte[] generateNonce(SecureRandom sr) { //TODO : nonce도 해야함..!! getMetadataSize 메소드를 abstract로 하나 만들기...
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		sr.nextBytes(nonce);
		return nonce;
	}
	
	/**
	 * Read nonce from given {@code InPut} instance.
	 * Size of the Nonce is determined by {@code CipherProperty}.
	 * 
	 * @return nonce from the {@code InPut}
	 * @see IVCipherProperty#NONCESIZE
	 * */
	protected byte[] readNonce(InPut in) {
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		int read = 0;
		while ((read += in.getSrc(nonce, read)) != nonce.length);
		return nonce;
	}
	
	/**
	 * @return <code>IVCipherProperty</code> of this <code>CipherUtil</code>
	 * */
	@Override
	protected abstract IVCipherProperty getCipherProperty();

	/**
	 * Generate iteration count, salt and nonce, init the cipher, write the metadata. 
	 * */
	@Override
	protected Cipher initEncrypt(OutPut out) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
		int iterationCount = generateIterationCount(sr);
		byte[] nonce = generateNonce(sr);
		Cipher c = getCipherInstance();
		try {
			c.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		out.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		out.consumeResult(salt);
		out.consumeResult(nonce);
		return c;
	}
	
	/**
	 * Read iteration count, salt and nonce, init the cipher. 
	 * */
	@Override
	protected Cipher initDecrypt(InPut in) throws NestedIOException {
		int iterationCount = readIterationCount(in);
		byte[] salt = readSalt(in);
		byte[] nonce = readNonce(in);
		
		if (!(keyMetadata.iterationRangeStart <= iterationCount && iterationCount < keyMetadata.iterationRangeEnd)) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRangeStart + " and " + keyMetadata.iterationRangeEnd);
		}
		Cipher c = getCipherInstance();
		try {
			c.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.value, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		return c;
	}

	/**
	 * @return String represents this CipherUtil instance. <code>super.fields()</code> will be followed by value of the nonce.
	 * */
	@Override
	protected String fields() {
		return super.fields() + ", Nonce Size : " + getCipherProperty().NONCESIZE + "byte";
	}

}
