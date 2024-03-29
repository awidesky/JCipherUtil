package io.github.awidesky.jCipherUtil.key.keyExchange.ecdh;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

import io.github.awidesky.jCipherUtil.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipherUtil.properties.EllipticCurveKeyExchangeProperty;

/**
 * An {@code EllipticCurveKeyExchanger} subclass that uses ECDH(Elliptic-curve Diffie–Hellman) Key exchange protocol.
 * About ECDH key exchange protocol, please see :<p>
 * <a href="https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange">
 * https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange<a>
 * <p>
 * <a href="https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman">
 * https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman<a>
 * */
public class ECDHKeyExchanger extends EllipticCurveKeyExchanger {

	/**
	 * Name of the elliptic curve.
	 * @see ECDHCurves
	 * */
	private final String curve;

	/**
	 * Creates the object with default curve(secp521r1).
	 * 
	 * @see ECDHCurves
	 * */
	public ECDHKeyExchanger() {
		this(ECDHCurves.secp521r1);
	}
	/**
	 * Creates the object with given {@code ECDHCurves} parameter.
	 * 
	 * @see ECDHCurves
	 * @param curve An elliptic curve for ECDH key exchange.
	 * */
	public ECDHKeyExchanger(ECDHCurves curve) {
		this(curve.name());
	}
	/**
	 * Creates the object with given name of the curve.
	 * Curves that is <i>not<i> specified in {@code ECDHCurves} may be supported(if JCE in user's JDK/JRE supports the curve), 
	 * but it is recommended to use one of the officially supported curves.
	 * <p>See <a href=https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names>
	 * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names<a> 
	 * for available elliptic curves.
	 * 
	 * @see ECDHCurves
	 * @param curve An elliptic curve for ECDH key exchange.
	 * */
	public ECDHKeyExchanger(String curve) {
		super(new EllipticCurveKeyExchangeProperty("EC", "ECDH"));
		this.curve = curve;
	}

	/**
	 * @return {@code AlgorithmParameterSpec} of this {@code ECDHKeyExchanger}
	 * */
	@Override
	protected AlgorithmParameterSpec getKeyPairParameterSpec() { return new ECGenParameterSpec(curve); }
	
	/**
	 * @return All names of the available curves that specified in {@code ECDHCurves}
	 */
	public static String[] getAvailableCurves() { return Stream.of(ECDHCurves.values()).map(ECDHCurves::name).toArray(String[]::new); }

	/** @return The name of the curve used in this {@code ECDHKeyExchanger} instance */
	@Override
	public String getCurve() { return curve; }

}
