/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.metadata;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

public class KeyProperty {

	private char[] password;
	private byte[] salt;
	int iterationCount;
	
	/**
	 * Initiate <code>KeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated because other necessary metadata(salt, iteration count) is unknown.
	 * <p>The <code>key</code> is encoded to hex representation(like {@link HexFormat#formatHex(byte[])}), 
	 * and use the result text to password.
	 * <p>This process is needed for consistency of key generating algorithm & metadata layout. 
	 * Since password salt and iteration count is included in cipherText header metadata,
	 * they should be used in every cases, otherwise, metadata scheme should be more complicated to let 
	 * cipher processor know if the cipherText uses salt&iteration count or not.
	 * And since <code>key</code> as byte array won't be salted, user might use same byte array multiple times,
	 * which causes vulnerability.
	 * 
	 * @param key byte data which will be encoded to hexadecimal format, and used for password.
	 * The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public KeyProperty(byte[] key) { this.password = byteArrToCharArr(Arrays.copyOf(key, key.length)); }
	/**
	 * Initiate <code>KeyProperty</code> with given <code>key</code>. Actual {@link javax.crypto.SecretKey}
	 * is not generated because other necessary metadata(salt, iteration count) is unknown.
	 * 
	 * @param key the password. The contents of the buffer are copied to protect against subsequent modification.
	 * */
	public KeyProperty(char[] password) { this.password = Arrays.copyOf(password, password.length); }
	
	/**
	 * Generate {@link javax.crypto.SecretKey} with given metadata.
	 * @param cm metadata of the Cipher. used to find key algorithm & key size.
	 * @param salt the salt. The contents of the buffer are copied to protect against subsequent modification.
	 * @param iterationCount the iteration count.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public SecretKeySpec genKey(CipherProperty cm, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException {
		this.salt =  Arrays.copyOf(salt, salt.length);
		this.iterationCount = iterationCount;
	    SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, this.salt, iterationCount, cm.KEYSIZE));
	    return new SecretKeySpec(pbeKey.getEncoded(), cm.KEY_ALGORITMH_NAME);
	}
	
	/**
	 * @return Salt value for the password-based key generation algorithm.
	 * The contents of the result were copied to protect against subsequent modification.
	 * */
	public byte[] getSalt() { return Arrays.copyOf(salt, salt.length); }
	/**
	 * @return Iteration count for the password-based key generation algorithm
	 * */
	public int getIterationCount() { return iterationCount; }
	
	/**
	 * Destroy the <code>SecretKeySpec</code>, password and metadata
	 * */
	public void destroy() throws DestroyFailedException {
		SecureRandom sr = new SecureRandom();
		//key.destroy(); only KerberosKey implement destroy method.
		//https://stackoverflow.com/questions/38276866/destroying-secretkey-throws-destroyfailedexception
		for(int i = 0; i < password.length; i++) password[i] = (char)sr.nextInt();
		for(int i = 0; i < salt.length; i++) salt[i] = (byte)sr.nextInt();
		iterationCount = sr.nextInt();
	}

	private static char[] byteArrToCharArr(byte[] password) {
    	char[] ret = new char[password.length * 2];
    	for(int i = 0; i < password.length; i++) {
    		ret[i * 2] = HexFormat.of().toHighHexDigit(password[i]);
    		ret[i * 2 + 1] = HexFormat.of().toLowHexDigit(password[i]);
    	}
		return ret;
	}
}
