package io.github.awidesky.jCipher.cipher.asymmetric.keyExchange;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import io.github.awidesky.jCipher.util.OmittedCipherException;

/**
 * https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange
 * */
public class ECDHKeyExchanger implements KeyExchanger {

	public static final String KEYALGORITHM = "EC";
	public static final String KEYAGREEMENTALGORITHM = "ECDH";
	public static final String curve = "secp256r1";
	// standard curvennames
	// secp256r1 [NIST P-256, X9.62 prime256v1]
	// secp384r1 [NIST P-384]
	// secp521r1 [NIST P-521]
	private static final KeyPairGenerator keyPairGenerator;
	private static final KeyAgreement keyAgreement;
	
	static {
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(KEYALGORITHM);
			keyAgreement = KeyAgreement.getInstance(KEYAGREEMENTALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	private KeyPair keyPair;
	
	@Override
	public PublicKey init() throws OmittedCipherException { //TODO : 생성자로?
		try {
			keyPairGenerator.initialize(new ECGenParameterSpec(curve));
			keyPair = keyPairGenerator.genKeyPair();
			return keyPair.getPublic();
		} catch (InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	@Override
	public byte[] exchangeKey(PublicKey other) throws OmittedCipherException {
		try {
			keyAgreement.init(keyPair.getPrivate());
			keyAgreement.doPhase(other, true);
			return keyAgreement.generateSecret();
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	@Override
	public String toString() {

		return "KeyPairGenerator : " + keyPairGenerator.getAlgorithm() + " from " + keyPairGenerator.getProvider()
			+ ", KeyAgreement : " + keyAgreement.getAlgorithm() + " from " + keyAgreement.getProvider()
			+ " with Curve : " + curve;
	}

}
