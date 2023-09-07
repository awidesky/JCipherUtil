package io.github.awidesky.jCipherUtil.properties;

import java.security.KeyPairGenerator;

import javax.crypto.KeyAgreement;
/**
 * Stores necessarily properties of the Key exchange process.
 * This includes the name of <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keypairgenerator-algorithms">key pair generation algorithm</a> and
 * <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyagreement-algorithms">key agreement algorithm</a>.
 * Every concrete subclass of {@code EllipticCurveKeyExchanger} must provide a {@code EllipticCurveKeyExchangeProperty} object
 * that explains the key exchange protocol to protected constructor of the superclass.
 * */
public class EllipticCurveKeyExchangeProperty {

	/**
	 * Name of the Elliptic-Curve keypair generation algorithm, like <code>EC</code> or <code>XDH</code>
	 * 
	 * @see KeyPairGenerator#getInstance(String)
	 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keypairgenerator-algorithms">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keypairgenerator-algorithmss</a>
	 * */
	public final String KEYPAIRALGORITHM;
	/**
	 * Name of the Elliptic-Curve key agreement algorithm, like <code>ECDH</code> or <code>XDH</code>
	 * 
	 * @see KeyAgreement#getInstance(String)
	 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyagreement-algorithms">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyagreement-algorithms</a>
	 * */
	public final String KEYAGREEMENTALGORITHM;
	
	/**
	 * Construct with given keypair generation algorithm and key agreement algorithm.
	 * */
	public EllipticCurveKeyExchangeProperty(String keyPairAlgorithm, String keyAgreementAlgorithm) {
		KEYPAIRALGORITHM = keyPairAlgorithm;
		KEYAGREEMENTALGORITHM = keyAgreementAlgorithm;
	}
	
}
