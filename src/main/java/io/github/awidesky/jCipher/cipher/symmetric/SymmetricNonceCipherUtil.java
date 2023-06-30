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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.properties.CipherProperty;
import io.github.awidesky.jCipher.properties.IVCipherProperty;
import io.github.awidesky.jCipher.util.IllegalMetadataException;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;

public abstract class SymmetricNonceCipherUtil extends SymmetricCipherUtil {

	protected byte[] nonce;
	
	protected SymmetricNonceCipherUtil(CipherProperty cipherMetadata, SymmetricKeyMetadata keyMetadata, int bufferSize) { super(cipherMetadata, keyMetadata, bufferSize); }

	/**
	 * Get {@code AlgorithmParameterSpec} of this cipher.
	 * default implementation returns an {@code IvParameterSpec} associated with the <code>nonce</code>.
	 * 
	 * */
	protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
		return new IvParameterSpec(nonce);
	}
	
	/**
	 * Generate random nonce with given {@code SecureRandom} instance.
	 * Size of the nonce is determined by {@code CipherProperty}.
	 * 
	 * @see IVCipherProperty#NONCESIZE
	 * */
	protected void generateNonce(SecureRandom sr) {
		nonce = new byte[getCipherProperty().NONCESIZE];
		sr.nextBytes(nonce);
	}
	/**
	 * Read nonce from given {@code MessageProvider} instance.
	 * Size of the Nonce is determined by {@code CipherProperty}.
	 * 
	 * @see IVCipherProperty#NONCESIZE
	 * */
	protected void readNonce(MessageProvider mp) {
		nonce = new byte[getCipherProperty().NONCESIZE];
		int read = 0;
		while ((read += mp.getSrc(nonce, read)) != nonce.length);
	}
	
	@Override
	protected abstract IVCipherProperty getCipherProperty();

	@Override
	protected void initEncrypt(MessageConsumer mc) throws NestedIOException {
		SecureRandom sr = new SecureRandom();
		generateSalt(sr);
		generateIterationCount(sr);
		generateNonce(sr);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
		mc.consumeResult(ByteBuffer.allocate(4).putInt(iterationCount).array());
		mc.consumeResult(salt);
		mc.consumeResult(nonce);
	}
	
	@Override
	protected void initDecrypt(MessageProvider mp) throws NestedIOException {
		readIterationCount(mp);
		readSalt(mp);
		readNonce(mp);
		
		if (!(keyMetadata.iterationRange[0] <= iterationCount && iterationCount < keyMetadata.iterationRange[1])) {
			throw new IllegalMetadataException("Unacceptable iteration count : " + iterationCount + ", must between " + keyMetadata.iterationRange[0] + " and " + keyMetadata.iterationRange[1]);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key.genKey(getCipherProperty().KEY_ALGORITMH_NAME, keyMetadata.keyLen, salt, iterationCount), getAlgorithmParameterSpec());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	protected String fields() {
		return super.fields() + ", Nonce Size : " + getCipherProperty().NONCESIZE + "byte";
	}

}
