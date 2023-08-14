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
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.properties.CipherProperty;
import io.github.awidesky.jCipherUtil.properties.IVCipherProperty;
import io.github.awidesky.jCipherUtil.util.exceptions.IllegalMetadataException;
import io.github.awidesky.jCipherUtil.util.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.util.exceptions.OmittedCipherException;

public abstract class SymmetricNonceCipherUtil extends SymmetricCipherUtil {

	/**
	 * Construct this {@code SymmetricCipherUtil} with given parameters.
	 * Subclasses should call this constructor with appropriate {@code CipherProperty} object(mostly static final field).
	 * */
	protected SymmetricNonceCipherUtil(CipherProperty cipherMetadata, KeyMetadata keyMetadata, KeySize keySize, SymmetricKeyMaterial key, int bufferSize) { super(cipherMetadata, keyMetadata, keySize, key, bufferSize); }

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
	 * Read nonce from given {@code InPut} instance.
	 * Size of the Nonce is determined by {@code CipherProperty}.
	 * 
	 * @return nonce from the {@code InPut}
	 * @see IVCipherProperty#NONCESIZE
	 * */
	protected byte[] readNonce(InPut mp) {
		byte[] nonce = new byte[getCipherProperty().NONCESIZE];
		int read = 0;
		while ((read += mp.getSrc(nonce, read)) != nonce.length);
		return nonce;
	}
	
	@Override
	protected abstract IVCipherProperty getCipherProperty();

	@Override
	protected Cipher initEncrypt(OutPut mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[keyMetadata.saltLen]; 
		sr.nextBytes(salt);
		int iterationCount = generateIterationCount(sr);
		byte[] nonce = generateNonce(sr);
		Cipher c = getCipherInstance();
		try {
			c.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.size, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		mc.consumeResult(nonce);
		return c;
	}
	
	@Override
	protected Cipher initDecrypt(InPut mp) throws NestedIOException {
		int iterationCount = readIterationCount(mp);
		byte[] salt = readSalt(mp);
		byte[] nonce = readNonce(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		Cipher c = getCipherInstance();
		try {
			c.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keySize.size, salt, iterationCount), getAlgorithmParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		return c;
	}

	@Override
	protected String fields() {
		return super.fields() + ", Nonce Size : " + getCipherProperty().NONCESIZE + "byte";
	}

}
