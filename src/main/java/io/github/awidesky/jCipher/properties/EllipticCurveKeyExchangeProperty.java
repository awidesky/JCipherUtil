package io.github.awidesky.jCipher.properties;

public class EllipticCurveKeyExchangeProperty {

	/** TODO : comment stub
	 * Name of the cipher algorithm, like <code>AES</code> or <code>ChaCha20-Poly1305</code>
	 * 
	 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names</a>
	 * */
	public final String KEYPAIRALGORITHM;
	/**
	 * Name of the cipher algorithm, like <code>AES</code> or <code>ChaCha20-Poly1305</code>
	 * 
	 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names</a>
	 * */
	public final String KEYAGREEMENTALGORITHM;
	
	public EllipticCurveKeyExchangeProperty(String keyPairAlgorithm, String keyAgreementAlgorithm) {
		KEYPAIRALGORITHM = keyPairAlgorithm;
		KEYAGREEMENTALGORITHM = keyAgreementAlgorithm;
	}
	
}
