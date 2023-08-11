package io.github.awidesky.jCipherUtil.key.keyExchange.xdh;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.stream.Stream;

import io.github.awidesky.jCipherUtil.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipherUtil.properties.EllipticCurveKeyExchangeProperty;


/**
 * An {@code EllipticCurveKeyExchanger} subclass that uses XDH(external Diffie–Hellman assumption) Key exchange protocol.
 * <a href="https://en.wikipedia.org/wiki/XDH_assumption">https://en.wikipedia.org/wiki/XDH_assumption<a>
 * */
public class XDHKeyExchanger extends EllipticCurveKeyExchanger {
	
	/**
	 * Name of the elliptic curve.
	 * @see XDHCurves
	 * */
	private final String curve;

	/**
	 * Creates the object with default curve(X25519).
	 * 
	 * @see XDHCurves
	 * */
	public XDHKeyExchanger() {
		this(XDHCurves.X25519);
	}
	/**
	 * Creates the object with given {@code XDHCurves} parameter.
	 * 
	 * @see XDHCurves
	 * @param curve An elliptic curve for XDH key exchange.
	 * */
	public XDHKeyExchanger(XDHCurves curve) {
		super(new EllipticCurveKeyExchangeProperty("XDH", "XDH"));
		this.curve = curve.name();
	}
	/**
	 * Creates the object with given name of the curve.
	 * Curves that is <i>not<i> specified in {@code XDHCurves} may be supported(if JCE in user's JDK/JRE supports the curve), 
	 * but it is recommended to use one of the officially supported curves.
	 * <p>See <a href=https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names>
	 * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names<a> 
	 * for available elliptic curves.
	 * 
	 * @see XDHCurves
	 * @param curve An elliptic curve for XDH key exchange.
	 * */
	public XDHKeyExchanger(String curve) {
		super(new EllipticCurveKeyExchangeProperty("XDH", "XDH"));
		this.curve = curve;
	}

	/**
	 * @return {@code AlgorithmParameterSpec} of this {@code XDHKeyExchanger}
	 * */
	@Override
	protected AlgorithmParameterSpec getKeyPairParameterSpec() { return new NamedParameterSpec(curve); }
	
	/**
	 * @return All names of the available curves that specified in {@code XDHCurves}
	 */
	public static String[] getAvailableCurves() { return Stream.of(XDHCurves.values()).map(XDHCurves::name).toArray(String[]::new); }

	/** @return The name of the curve used in this {@code XDHKeyExchanger} instance */
	@Override
	public String getCurve() { return curve; }
}
