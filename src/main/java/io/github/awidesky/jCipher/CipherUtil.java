/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HexFormat;

import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.KeyProperty;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.NestedOmittedCipherException;


/**
 * An utility that provides easy encrypt/decrypt process from/to various input/output.
 * <p>The {@code CipherUtil} interface provides two generic encrypt/decrypt method named
 * {@link CipherUtil#encrypt(MessageProvider, MessageConsumer)} and {@link CipherUtil#decrypt(MessageProvider, MessageConsumer)},
 * that can be used to encrypt and decrypt from/to many types.
 * <p>Also, The {@code CipherUtil} interface provides several utility encrypt/decrypt method like 
 * {@link CipherUtil#encryptToBase64(MessageProvider)}, {@link CipherUtil#decryptToBase64(MessageProvider)}, {@link CipherUtil#decryptToString(MessageProvider, Charset)}  
 * that returns result of cipher process as specified form(Base64 encoded {@code String} hex formated {@code String}, {@code String} encoded with given character set, 
 * single {@code byte[]} buffer, etc)
 * 
 * @see MessageProvider
 * @see MessageConsumer
 * @see AbstractCipherUtil
 * */
public interface CipherUtil {
	
	/**
	 * Initialize this <code>CipherUtil</code> with given <code>password</code>
	 * 
	 * @return this instance
	 * */
	public CipherUtil init(char[] password);
	/**
	 * Initialize this <code>CipherUtil</code> with given <code>password</code>
	 * Given byte array does not used directly as a key. instead, it is converted to <code>String</code> via {@link KeyProperty#byteArrToCharArr},
	 * and then used as a password.
	 * This is for consistency of salting, PBE algorithm, cipher metadata save protocol.
	 * 
	 * @return this instance
	 * */
	public CipherUtil init(byte[] password);

	/**
	 * Simple way to encrypt from a source to a destination.
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc CipherUtil data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void encrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, NestedOmittedCipherException;
	/**
	 * Simple way to decrypt from a source to a destination.
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @param mc Plain data Consumer that writes decrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void decrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, NestedOmittedCipherException;
	
	
	/**
	 * Encrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return the <code>byte</code> array that has all encrypted data
	 * @throws NestedIOException 
	 * @throws NestedOmittedCipherException 
	 * */
	public default byte[] encryptToSingleBuffer(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		encrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}
	/**
	 * Encrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return <code>Base64</code> text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToBase64(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		return Base64.getEncoder().encodeToString(encryptToSingleBuffer(mp));
	}
	/**
	 * Encrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToHexString(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		return HexFormat.of().formatHex(encryptToSingleBuffer(mp));
	}
	/**
	 * Decrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return the <code>byte</code> array that has all decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default byte[] decryptToSingleBuffer(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		decrypt(mp, MessageConsumer.to(bos));
		return bos.toByteArray();
	}
	/**
	 * Decrypt whole data and encode it to <code>String</code>
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return text that encoded from decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToString(MessageProvider mp, Charset encoding) throws NestedIOException, NestedOmittedCipherException {
		return new String(decryptToSingleBuffer(mp), encoding);
	}
	/**
	 * Decrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return <code>Base64</code> text that encoded from decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToBase64(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		return Base64.getEncoder().encodeToString(decryptToSingleBuffer(mp));
	}

	/**
	 * Decrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws NestedOmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToHexString(MessageProvider mp) throws NestedIOException, NestedOmittedCipherException {
		return HexFormat.of().formatHex(decryptToSingleBuffer(mp));
	}
	
}
