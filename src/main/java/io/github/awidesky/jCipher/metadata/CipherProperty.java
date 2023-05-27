/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.metadata;

public class CipherProperty {
	/**
	 * Name of the cipher algorithm, like <code>AES</code> or <code>ChaCha20-Poly1305</code>
	 * {@link https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names}
	 * */
	public final String ALGORITMH_NAME;
	
	/**
	 * Mode of the cipher algorithm, like <code>CBC</code> or <code>GCM</code>
	 * {@link https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-modes}
	 * */
	public final String ALGORITMH_MODE;
	
	/**
	 * Padding of the cipher algorithm, like <code>NoPadding</code> or <code>PKCS5Padding</code>
	 * {@link https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-paddings}
	 * */
	public final String ALGORITMH_PADDING;
	
	/**
	 * Name of the key algorithm, like <code>AES</code> or <code>ChaCha20</code>
	 * {@link https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#secretkeyfactory-algorithms}
	 * */
	public final String KEY_ALGORITMH_NAME;
	
	/**
	 * Size of nonce(Initial Vector) in bytes
	 * */
	public final int NONCESIZE;
	/**
	 * Size of key in bytes
	 * */
	public final int KEYSIZE;
	
	public CipherProperty(String algorithmName, String algorithmMode, String algorithmPadding, String keyAlgorithmName, int nonceSize, int keySize) {
		this.ALGORITMH_NAME = algorithmName;
		this.ALGORITMH_MODE = algorithmMode;
		this.ALGORITMH_PADDING = algorithmPadding;
		this.KEY_ALGORITMH_NAME = keyAlgorithmName;
		this.NONCESIZE = nonceSize;
		this.KEYSIZE = keySize;
	}
}
