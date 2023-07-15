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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HexFormat;

import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.util.NestedIOException;
import io.github.awidesky.jCipher.util.OmittedCipherException;


/**
 * An utility that provides easy encrypt/decrypt methods from/to various input/output.
 * <p>The {@code CipherUtil} interface provides two generic encrypt/decrypt method named
 * {@link CipherUtil#encrypt(MessageProvider, MessageConsumer)} and {@link CipherUtil#decrypt(MessageProvider, MessageConsumer)},
 * that can be used to encrypt and decrypt from/to many types.
 * <p>Also, The {@code CipherUtil} interface provides several utility encrypt/decrypt method like 
 * {@link CipherUtil#encryptToBase64(MessageProvider)}, {@link CipherUtil#decryptToBase64(MessageProvider)}, {@link CipherUtil#decryptToString(MessageProvider, Charset)}  
 * that returns result of cipher process as specified form(Base64 encoded {@code String} hex formated {@code String}, {@code String} encoded with given character set, 
 * single {@code byte[]} buffer, etc)
 * <p>Every methods in this interface is thread-safe. Each call is run with new {@code Cipher} instance, and does not effect anything to the {@code CipherUtil} instance.
 * Every cipher process by this interface's methods is done before return. If you need multiple-part encryption or decryption operation, see {@link UpdatableCipherUtil}
 * 
 * 
 * @see MessageProvider
 * @see MessageConsumer
 * @see SymmetricCipherUtil
 * @see AsymmetricCipherUtil
 * */
public interface CipherUtil {

	/**
	 * Simple way to encrypt from a source to a destination.
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @param mc CipherUtil data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void encrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException;
	/**
	 * Simple way to decrypt from a source to a destination.
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @param mc Plain data Consumer that writes decrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void decrypt(MessageProvider mp, MessageConsumer mc) throws NestedIOException, OmittedCipherException;
	
	
	/**
	 * Simple way to encrypt from a {@code InputStreamr} to a {@code OutputStream}.<p>
	 * Both <code>Stream</code>s are closed after cipher process is finished.
	 * 
	 * @param in Source for encryption
	 * @param out The destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default void encrypt(InputStream in, OutputStream out) throws NestedIOException, OmittedCipherException {
		encrypt(MessageProvider.from(in), MessageConsumer.to(out));
	}

	/**
	 * Simple way to decrypt from a {@code InputStreamr} to a {@code OutputStream}.<p>
	 * Both <code>Stream</code>s are closed after cipher process is finished.
	 * 
	 * @param in Source for encryption
	 * @param out The destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default void decrypt(InputStream in, OutputStream out) throws NestedIOException, OmittedCipherException {
		decrypt(MessageProvider.from(in), MessageConsumer.to(out));
	}
	
	/**
	 * Encrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return the <code>byte</code> array that has all encrypted data
	 * @throws NestedIOException 
	 * @throws OmittedCipherException 
	 * */
	public default byte[] encryptToSingleBuffer(MessageProvider mp) throws NestedIOException, OmittedCipherException {
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
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToBase64(MessageProvider mp) throws NestedIOException, OmittedCipherException {
		return Base64.getEncoder().encodeToString(encryptToSingleBuffer(mp));
	}
	/**
	 * Encrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp Plain data Provider of source for encryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToHexString(MessageProvider mp) throws NestedIOException, OmittedCipherException {
		return HexFormat.of().formatHex(encryptToSingleBuffer(mp));
	}
	/**
	 * Decrypt whole data into single <code>byte[]</code> and return it
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return the <code>byte</code> array that has all decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default byte[] decryptToSingleBuffer(MessageProvider mp) throws NestedIOException, OmittedCipherException {
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
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToString(MessageProvider mp, Charset encoding) throws NestedIOException, OmittedCipherException {
		return new String(decryptToSingleBuffer(mp), encoding);
	}
	/**
	 * Decrypt whole data and represent the binary data as <code>Base64</code> encoding
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return <code>Base64</code> text that encoded from decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToBase64(MessageProvider mp) throws NestedIOException, OmittedCipherException {
		return Base64.getEncoder().encodeToString(decryptToSingleBuffer(mp));
	}

	/**
	 * Decrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param mp CipherUtil data Provider of source for decryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToHexString(MessageProvider mp) throws NestedIOException, OmittedCipherException {
		return HexFormat.of().formatHex(decryptToSingleBuffer(mp));
	}
	
	
	public CipherTunnel cipherEncryptTunnel(MessageProvider mp, MessageConsumer mc);
	public CipherTunnel cipherDecryptTunnel(MessageProvider mp, MessageConsumer mc);
	public UpdatableEncrypter UpdatableEncryptCipher(MessageConsumer mc);
	public UpdatableDecrypter UpdatableDecryptCipher(MessageProvider mp);
	
}
