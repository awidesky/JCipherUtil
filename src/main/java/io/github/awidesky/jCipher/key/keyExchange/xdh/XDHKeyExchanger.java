package io.github.awidesky.jCipher.key.keyExchange.xdh;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.stream.Stream;

import io.github.awidesky.jCipher.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipher.properties.EllipticCurveKeyExchangeProperty;
import io.github.awidesky.jCipher.util.exceptions.OmittedCipherException;

public class XDHKeyExchanger extends EllipticCurveKeyExchanger {

	
	private XDHCurves curve = XDHCurves.X25519;

	
	public XDHKeyExchanger() {
		super(new EllipticCurveKeyExchangeProperty("XDH", "XDH"));
	}

	/**
	 * Init with default curve
	 * */
	@Override
	public PublicKey init() throws OmittedCipherException {
		return init(XDHCurves.X25519);
	}
	public PublicKey init(XDHCurves curve) {
		this.curve = curve;
		return init(curve.name());
	}
	@Override
	public PublicKey init(String curveName) throws OmittedCipherException {
		this.curve = XDHCurves.valueOf(curveName);
		return generateKeyPair();
	}
	
	@Override
	protected AlgorithmParameterSpec getKeyPairParameterSpec() { return new NamedParameterSpec(curve.name()); }
	
	@Override
	public String[] getAvailableCurves() { return Stream.of(XDHCurves.values()).map(XDHCurves::name).toArray(String[]::new); }

	@Override
	public String getCurve() { return curve.curveName; }
}
