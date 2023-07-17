package io.github.awidesky.jCipher.key.keyExchange.xdh;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.stream.Stream;

import io.github.awidesky.jCipher.key.keyExchange.KeyExchanger;
import io.github.awidesky.jCipher.util.exceptions.OmittedCipherException;

public class XDHKeyExchanger extends KeyExchanger {

	public static final String KEYPAIRALGORITHM = "XDH";
	public static final String KEYAGREEMENTALGORITHM = "XDH";
	private XDHCurves curve = XDHCurves.X25519;

	@Override
	protected String getKeyAgreementAlgorithm() { return KEYAGREEMENTALGORITHM; }

	@Override
	protected String getKeyPairAlgorithm() { return KEYPAIRALGORITHM; }

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
