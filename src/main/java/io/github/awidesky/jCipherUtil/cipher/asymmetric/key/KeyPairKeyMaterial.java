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

public class KeyPairKeyMaterial extends AsymmetricKeyMaterial {

	private final PublicKeyOnlyKeyMaterial publicKey;
	private final PrivateKeyOnlyKeyMaterial privateKey;
	
	public KeyPairKeyMaterial(KeyPair keyPair) {
		this(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
	}
	public KeyPairKeyMaterial(String publicKey, String privateKey) {
		this.publicKey = new PublicKeyOnlyKeyMaterial(publicKey);
		this.privateKey = new PrivateKeyOnlyKeyMaterial(privateKey);
	}
	public KeyPairKeyMaterial(byte[] publicKey, byte[] privateKey) {
		this.publicKey = new PublicKeyOnlyKeyMaterial(publicKey);
		this.privateKey = new PrivateKeyOnlyKeyMaterial(privateKey);
	}
	
	@Override
	public KeyPair getKey(String algorithm) {
		return new KeyPair(publicKey.getKey(algorithm).getPublic(), privateKey.getKey(algorithm).getPrivate());
	}

}
