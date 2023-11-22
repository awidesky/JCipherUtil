package io.github.awidesky.jCipherUtil.key.keyExchange;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;

import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.properties.EllipticCurveKeyExchangeProperty;

/**
 * An abstract base class for Key exchange process via Elliptic curve key agreement(key exchange) protocol like Diffie-Hellman algorithm.
 * @see KeyAgreement
 * @see EllipticCurveKeyExchangeProperty
 * */
public abstract class EllipticCurveKeyExchanger {
	
	private final KeyPairGenerator keyPairGenerator;
	private final KeyAgreement keyAgreement;
	private KeyPair keyPair;
	protected final EllipticCurveKeyExchangeProperty property; 
	
	/** 
	 * initiate with given {@code EllipticCurveKeyExchangeProperty}.
	 * Subclasses should call this constructor with appropriate {@code EllipticCurveKeyExchangeProperty} object(mostly a {@code static final} field).
	 * */
	protected EllipticCurveKeyExchanger(EllipticCurveKeyExchangeProperty property) {
		this.property = property;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(property.KEYPAIRALGORITHM);
			keyAgreement = KeyAgreement.getInstance(property.KEYAGREEMENTALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * @return {@code AlgorithmParameterSpec} of this {@code EllipticCurveKeyExchanger}, 
	 * which usually defined in the subclasses.
	 * */
	protected abstract AlgorithmParameterSpec getKeyPairParameterSpec();
	/**
	 * @return name of the elliptic curve that is currently used(if non was specified, default curve)
	 * */
	public abstract String getCurve();
	
	/**
	 * Generate and return new {@code KeyPair}.
	 * 
	 * @return {@code PublicKey} of generated {@code KeyPair}
	 * */
	protected PublicKey generateKeyPair() {
		try {
			keyPairGenerator.initialize(getKeyPairParameterSpec());
			keyPair = keyPairGenerator.genKeyPair();
			return keyPair.getPublic();
		} catch (InvalidAlgorithmParameterException e) {
			throw new OmittedCipherException(e);
		}
	}
	
	/**
	 * Initiate the key exchange protocol and return new {@code PublicKey}. Returned {@code PublicKey} must be
	 * transfered to the peer, and peer's {@code PublicKey} must be received and passed to {@code EllipticCurveKeyExchanger#exchangeKey(PublicKey)}
	 * to finish the key exchange protocol.
	 * 
	 * @return {@code PublicKey} of generated {@code KeyPair}
	 * */
	public PublicKey init() {
		return generateKeyPair();
	}
	
	/**
	 * Finish the key agreement process with given {@code PublicKey} of the peer and generate shared secret.
	 * 
	 * @param other {@code PublicKey} obtained from peer
	 * @return byte array contains generated shared secret(can be used as a secret key for {@code SymmetricCipherUtil}
	 * */
	public byte[] exchangeKey(PublicKey other) throws OmittedCipherException {
		try {
			keyAgreement.init(keyPair.getPrivate());
			keyAgreement.doPhase(other, true);
			return keyAgreement.generateSecret();
		} catch (InvalidKeyException e) {
			throw new OmittedCipherException(e);
		}
	}

	
	/**
	 * Returns a {@code String} that represents this {@code EllipticCurveKeyExchanger} object.
	 * @return {@code String} contains simple class name, and algorithm/provider name of the {@code KeyPairGenerator} and {@code KeyAgreement}
	 * used in this {@code EllipticCurveKeyExchanger} object.
	 * */
	@Override
	public String toString() {
		return getClass().getSimpleName() + " [KeyPairGenerator : \"" + keyPairGenerator.getAlgorithm() + "\" from \"" + keyPairGenerator.getProvider()
			+ "\" with curve : \"" + getCurve() + "\", KeyAgreement : \"" + keyAgreement.getAlgorithm() + "\" from \"" + keyAgreement.getProvider() + "\"]";
	}

	
}
