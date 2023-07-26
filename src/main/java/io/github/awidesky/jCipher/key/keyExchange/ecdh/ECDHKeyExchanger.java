package io.github.awidesky.jCipher.key.keyExchange.ecdh;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

import io.github.awidesky.jCipher.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipher.properties.EllipticCurveKeyExchangeProperty;
import io.github.awidesky.jCipher.util.exceptions.OmittedCipherException;

/**
 * https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange
 * */
public class ECDHKeyExchanger extends EllipticCurveKeyExchanger {

	private ECDHCurves curve = ECDHCurves.secp521r1; // TODO : constructor with curve


	public ECDHKeyExchanger() {
		super(new EllipticCurveKeyExchangeProperty("EC", "ECDH"));
	}


	/**
	 * Init with default curve
	 * */
	@Override
	public PublicKey init() throws OmittedCipherException {
		return init(ECDHCurves.secp521r1);
	}
	public PublicKey init(ECDHCurves curve) {
		this.curve = curve;
		return init(curve.name());
	}
	@Override
	public PublicKey init(String curveName) throws OmittedCipherException {
		this.curve = ECDHCurves.valueOf(curveName);
		return generateKeyPair();
	}

	@Override
	protected AlgorithmParameterSpec getKeyPairParameterSpec() { return new ECGenParameterSpec(curve.name()); }
	
	@Override
	public String[] getAvailableCurves() { return Stream.of(ECDHCurves.values()).map(ECDHCurves::name).toArray(String[]::new); }

	@Override
	public String getCurve() { return curve.curveName; }

}
