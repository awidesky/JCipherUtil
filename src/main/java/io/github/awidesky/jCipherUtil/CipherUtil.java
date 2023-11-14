/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HexFormat;

import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.exceptions.NestedIOException;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.util.CipherMode;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.CipherUtilInputStream;
import io.github.awidesky.jCipherUtil.util.CipherUtilOutputStream;


/**
 * An utility that provides easy encrypt/decrypt methods from/to various
 * input/output.
 * <p>
 * The {@code CipherUtil} interface provides two generic encrypt/decrypt method
 * named {@link CipherUtil#encrypt(InPut, OutPut)} and
 * {@link CipherUtil#decrypt(InPut, OutPut)}, that can be used to encrypt and
 * decrypt from/to many types.
 * <p>
 * Also, The {@code CipherUtil} interface provides several utility
 * encrypt/decrypt method like {@link CipherUtil#encryptToBase64(InPut)},
 * {@link CipherUtil#decryptToBase64(InPut)},
 * {@link CipherUtil#decryptToString(InPut, Charset)} that returns result of
 * cipher process as specified form(Base64 encoded {@code String} hex formated
 * {@code String}, {@code String} encoded with given character set, single
 * {@code byte[]} buffer, etc)
 * <p>
 * Every methods in this interface is thread-safe. Each call is run with new
 * {@code Cipher} instance, and does not effect anything to the
 * {@code CipherUtil} instance. Every cipher process by this interface's methods
 * is done before return. If you need multiple-part encryption or decryption
 * operation, use {@link CipherEngine}, {@link CipherTunnel},
 * {@link CipherUtilInputStream} or {@link CipherUtilInputStream}.
 * 
 * 
 * @see InPut
 * @see OutPut
 * @see AbstractCipherUtil
 * @see SymmetricCipherUtil
 * @see AsymmetricCipherUtil
 */
public interface CipherUtil {

	/**
	 * Simple way to encrypt from a source to a destination.
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @param out CipherUtil data Consumer that writes encrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void encrypt(InPut in, OutPut out) throws NestedIOException, OmittedCipherException;
	/**
	 * Simple way to decrypt from a source to a destination.
	 * 
	 * @param in CipherUtil data Provider of source for decryption
	 * @param out Plain data Consumer that writes decrypted data to designated destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public void decrypt(InPut in, OutPut out) throws NestedIOException, OmittedCipherException;
	
	
	/**
	 * Simple way to encrypt from a {@code InputStreamr} to a {@code OutputStream}.<p>
	 * Both streams are closed after cipher process is finished.
	 * 
	 * @param in Source for encryption
	 * @param out The destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default void encrypt(InputStream in, OutputStream out) throws NestedIOException, OmittedCipherException {
		encrypt(InPut.from(in), OutPut.to(out));
	}

	/**
	 * Simple way to decrypt from a {@code InputStreamr} to a {@code OutputStream}.<p>
	 * Both streams are closed after cipher process is finished.
	 * 
	 * @param in Source for encryption
	 * @param out The destination 
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default void decrypt(InputStream in, OutputStream out) throws NestedIOException, OmittedCipherException {
		decrypt(InPut.from(in), OutPut.to(out));
	}
	
	/**
	 * Encrypt whole data into single {@code byte[]} and return it
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @return the {@code byte} array that has all encrypted data
	 * @throws NestedIOException 
	 * @throws OmittedCipherException 
	 * */
	public default byte[] encryptToSingleBuffer(InPut in) throws NestedIOException, OmittedCipherException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		encrypt(in, OutPut.to(bos));
		return bos.toByteArray();
	}
	/**
	 * Encrypt whole data and represent the binary data as {@code Base64} encoding
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @return {@code Base64} text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToBase64(InPut in) throws NestedIOException, OmittedCipherException {
		return Base64.getEncoder().encodeToString(encryptToSingleBuffer(in));
	}
	/**
	 * Encrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param in Plain data Provider of source for encryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String encryptToHexString(InPut in) throws NestedIOException, OmittedCipherException {
		return HexFormat.of().formatHex(encryptToSingleBuffer(in));
	}
	/**
	 * Decrypt whole data into single {@code byte[]} and return it
	 * 
	 * @param in CipherUtil data Provider of source for decryption
	 * @return the {@code byte[]} array that has all decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default byte[] decryptToSingleBuffer(InPut in) throws NestedIOException, OmittedCipherException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		decrypt(in, OutPut.to(bos));
		return bos.toByteArray();
	}
	/**
	 * Decrypt whole data and encode it to {@code String}
	 * 
	 * @param in CipherUtil data Provider of source for decryption
	 * @return text that encoded from decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToString(InPut in, Charset encoding) throws NestedIOException, OmittedCipherException {
		return new String(decryptToSingleBuffer(in), encoding);
	}
	/**
	 * Decrypt whole data and represent the binary data as {@code Base64} encoding
	 * 
	 * @param in CipherUtil data Provider of source for decryption
	 * @return {@code Base64} text that encoded from decrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToBase64(InPut in) throws NestedIOException, OmittedCipherException {
		return Base64.getEncoder().encodeToString(decryptToSingleBuffer(in));
	}

	/**
	 * Decrypt whole data and represent the binary data as hex format(e.g. 5f3759df)
	 * 
	 * @param in CipherUtil data Provider of source for decryption
	 * @return hex format text that encoded from encrypted data
	 * @throws NestedIOException if {@code IOException} is thrown. if this cipher process related with
	 * external resources(like {@code File}, caller should catch {@code NestedIOException}.  
	 * @throws OmittedCipherException if a cipher-related, omitted exceptions that won't happen unless
	 * there's a internal flaw in the cipher library occurs.
	 * */
	public default String decryptToHexString(InPut in) throws NestedIOException, OmittedCipherException {
		return HexFormat.of().formatHex(decryptToSingleBuffer(in));
	}
	
	
	/**
	 * Return a new {@code CipherTunnel} that transfer data from input to output,
	 * while encrypting/decrypting the data.
	 * <p>
	 * Cipher operation of the returned {@code CipherTunnel} instance is irrelevant
	 * from that of this {@code CipherUtil} instance.
	 * Every metadata(including key) and cipher algorithm follow those of the {@code CipherUtil}
	 * instance, but using the returned {@code CipherTunnel} instance
	 * will not affect internal cipher operation of this {@code CipherUtil} instance
	 * (in other words, each uses different {@code javax.crypto.Cipher} object).
	 * 
	 * @see CipherTunnel
	 * 
	 * @param in   the input where the plain source data resides
	 * @param out  the output destination for the encrypted/decrypted data to be
	 *             written
	 * @param mode operation mode. either {@code CipherUtil#ENCRYPT_MODE} or
	 *             {@code CipherUtil#ENCRYPT_MODE}
	 * @return a new {@code CipherTunnel} as given mode.
	 */
	public CipherTunnel cipherTunnel(InPut in, OutPut out, CipherMode mode);
	
	/**
	 * Returns a new {@code CipherEngine} with given mode.
	 * <p>
	 * Cipher operation of the returned {@code CipherEngine} instance is irrelevant
	 * from that of this {@code CipherUtil} instance.
	 * Every metadata(including key) and cipher algorithm follow those of the {@code CipherUtil}
	 * instance, but using the returned {@code CipherEngine} instance
	 * will not affect internal cipher operation of this {@code CipherUtil} instance
	 * (in other words, each uses different {@code javax.crypto.Cipher} object).
	 * 
	 * @see CipherEngine
	 * 
	 * @param mode operation mode. either {@code CipherUtil#ENCRYPT_MODE} or {@code CipherUtil#ENCRYPT_MODE}
	 * @return a new {@code CipherEngine} as given mode.
	 */
	public CipherEngine cipherEngine(CipherMode mode);
	
	/**
	 * Returns a new {@code CipherUtilOutputStream} connected with given {@code OutputStream}.
	 * <p>
	 * Cipher operation of the returned {@code CipherUtilOutputStream} instance is irrelevant
	 * from that of this {@code CipherUtil} instance.
	 * Every metadata(including key) and cipher algorithm follow those of the {@code CipherUtil}
	 * instance, but using the returned {@code CipherUtilOutputStream} instance
	 * will not affect internal cipher operation of this {@code CipherUtil} instance
	 * (in other words, each uses different {@code javax.crypto.Cipher} object).
	 * 
	 * @param out underlying output stream
	 * @param mode operation mode. either {@code CipherUtil#ENCRYPT_MODE} or {@code CipherUtil#ENCRYPT_MODE}
	 * @return a new {@code CipherUtilOutputStream} ad given mode.
	 */
	public CipherUtilOutputStream outputStream(OutputStream out, CipherMode mode);
	/**
	 * Returns a new {@code CipherUtilInputStream} connected with given {@code InputStream}.
	 * <p>
	 * Cipher operation of the returned {@code CipherUtilInputStream} instance is irrelevant
	 * from that of this {@code CipherUtil} instance.
	 * Every metadata(including key) and cipher algorithm follow those of the {@code CipherUtil}
	 * instance, but using the returned {@code CipherUtilInputStream} instance
	 * will not affect internal cipher operation of this {@code CipherUtil} instance
	 * (in other words, each uses different {@code javax.crypto.Cipher} object).
	 * 
	 * @param in underlying input stream
	 * @param mode operation mode. either {@code CipherUtil#ENCRYPT_MODE} or {@code CipherUtil#ENCRYPT_MODE}
	 * @return a new {@code CipherUtilInputStream} ad given mode.
	 */
	public CipherUtilInputStream inputStream(InputStream in, CipherMode mode);
	
	/**
	 * Destroy or clear associated secret(key), therefore make this {@code CipherUtil} unable to use anymore. 
	 * */
	public void destroyKey();
	
	
}
