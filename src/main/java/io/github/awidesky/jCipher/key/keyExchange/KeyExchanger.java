package io.github.awidesky.jCipher.key.keyExchange;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;

import io.github.awidesky.jCipher.util.exceptions.OmittedCipherException;

public abstract class KeyExchanger {
	
	private final KeyPairGenerator keyPairGenerator;
	private final KeyAgreement keyAgreement;
	private KeyPair keyPair;
	
	public KeyExchanger() {
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(getKeyPairAlgorithm());
			keyAgreement = KeyAgreement.getInstance(getKeyAgreementAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	protected abstract String getKeyAgreementAlgorithm();
	protected abstract String getKeyPairAlgorithm();
	protected abstract AlgorithmParameterSpec getKeyPairParameterSpec();
	public abstract String[] getAvailableCurves();
	public abstract PublicKey init() throws OmittedCipherException;
	public abstract PublicKey init(String curveName) throws OmittedCipherException;
	public abstract String getCurve();
	

	protected PublicKey generateKeyPair() { //TODO : 생성자로?
		try {
			keyPairGenerator.initialize(getKeyPairParameterSpec());
			keyPair = keyPairGenerator.genKeyPair();
			return keyPair.getPublic();
		} catch (InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}
	

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
		return getClass().getSimpleName() + " [\"" + keyPairGenerator.getAlgorithm() + "\" from \"" + keyPairGenerator.getProvider()
			+ "\", KeyAgreement : \"" + keyAgreement.getAlgorithm() + "\" from \"" + keyAgreement.getProvider() + "\"]";
	}

	
}
