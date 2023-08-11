/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.properties;

public class CipherProperty {
	/**
	 * Name of the cipher algorithm, like <code>AES</code> or <code>ChaCha20-Poly1305</code>
	 * 
	 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names</a>
	 * */
	public final String ALGORITMH_NAME;
	
	/**
	 * Mode of the cipher algorithm, like <code>CBC</code> or <code>GCM</code>
	 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-modes">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-modes</a>
	 * */
	public final String ALGORITMH_MODE;
	
	/**
	 * Padding of the cipher algorithm, like <code>NoPadding</code> or <code>PKCS5Padding</code>
	 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-paddings">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-paddings</a>
	 * */
	public final String ALGORITMH_PADDING;
	
	/**
	 * Name of the key algorithm, like <code>AES</code> or <code>ChaCha20</code>
	 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#secretkeyfactory-algorithms</a>
	 * */
	public final String KEY_ALGORITMH_NAME;

	/**
	 * Initialize <code>CipherProperty</code> with given parameters.
	 *
	 * @param algorithmName Name of the cipher algorithm, like <code>AES</code> or <code>ChaCha20-Poly1305</code>
	 * @param algorithmMode Mode of the cipher algorithm, like <code>CBC</code> or <code>GCM</code>
	 * @param algorithmPadding Padding of the cipher algorithm, like <code>NoPadding</code> or <code>PKCS5Padding</code>
	 * @param keyAlgorithmName Name of the key algorithm, like <code>AES</code> or <code>ChaCha20</code>
	 */
	public CipherProperty(String algorithmName, String algorithmMode, String algorithmPadding, String keyAlgorithmName) {
		this.ALGORITMH_NAME = algorithmName;
		this.ALGORITMH_MODE = algorithmMode;
		this.ALGORITMH_PADDING = algorithmPadding;
		this.KEY_ALGORITMH_NAME = keyAlgorithmName;
	}
	
	protected String fields() {
		return "ALGORITMH_NAME=" + ALGORITMH_NAME + ", ALGORITMH_MODE=" + ALGORITMH_MODE
				+ ", ALGORITMH_PADDING=" + ALGORITMH_PADDING + ", KEY_ALGORITMH_NAME=" + KEY_ALGORITMH_NAME;
	}
	
	@Override
	public String toString() {
		return "CipherProperty [" + fields() + "]";
	}
}
