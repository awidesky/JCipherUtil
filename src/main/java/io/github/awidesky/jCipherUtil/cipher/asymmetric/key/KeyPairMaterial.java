/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipherUtil.cipher.asymmetric.key;

import java.security.KeyPair;

import io.github.awidesky.jCipherUtil.properties.CipherProperty;

/**
 * A wrapper class for {@code KeyPair}.
 * Basically a pair of {@code PublicKeyMaterial} and {@code PrivateKeyMaterial}.
 * One {@code KeyPairMaterial} can used for generating multiple asymmetric cipher via 
 * {@code KeyPairMaterial#getKey(String)}.
 * 
 * @see PublicKeyMaterial
 * @see PrivateKeyMaterial
 * */
public class KeyPairMaterial extends AsymmetricKeyMaterial {

	private final PublicKeyMaterial publicKey;
	private final PrivateKeyMaterial privateKey;
	
	/** Creates with given {@code KeyPair} */
	public KeyPairMaterial(KeyPair keyPair) {
		this(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
	}
	/** Creates with given {@code base64} encoded {@code String}s. */
	public KeyPairMaterial(String publicKey, String privateKey) {
		this.publicKey = new PublicKeyMaterial(publicKey);
		this.privateKey = new PrivateKeyMaterial(privateKey);
	}
	/** Creates with given key binaries. */
	public KeyPairMaterial(byte[] publicKey, byte[] privateKey) {
		this.publicKey = new PublicKeyMaterial(publicKey);
		this.privateKey = new PrivateKeyMaterial(privateKey);
	}
	/** Creates with given {@code PublicKeyMaterial} and {@code PrivateKeyMaterial}. */
	public KeyPairMaterial(PublicKeyMaterial publicKey, PrivateKeyMaterial privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	/** 
	 * Return {@code KeyPair} as given {@code algorithm}.
	 * 
	 * @see CipherProperty#KEY_ALGORITMH_NAME
	 * */
	@Override
	public KeyPair getKey(String algorithm) {
		return new KeyPair(publicKey.getKey(algorithm).getPublic(), privateKey.getKey(algorithm).getPrivate());
	}

}