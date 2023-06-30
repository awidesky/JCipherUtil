package io.github.awidesky.jCipher.cipher.asymmetric.keyExchange;

import java.security.PublicKey;

import io.github.awidesky.jCipher.util.OmittedCipherException;

public interface KeyExchanger {

	public PublicKey init() throws OmittedCipherException;
	
	public byte[] exchangeKey(PublicKey other) throws OmittedCipherException;
	
}
