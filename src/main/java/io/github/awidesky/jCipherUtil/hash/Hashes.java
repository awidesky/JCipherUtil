package io.github.awidesky.jCipherUtil.hash;

import java.util.Base64;
import java.util.HexFormat;
import java.util.function.Supplier;
import java.util.zip.Checksum;

import io.github.awidesky.jCipherUtil.messageInterface.InPut;

/**
 * An enum representing all {@code Hash} interface subclasses.
 * Also contains one-call digest methods
 * ({@code Hashes#toBytes(Hash, InPut)}, {@code Hashes#toBase64(Hash, InPut)}, and
 * {@code Hashes#toHex(Hash, InPut)}) that process hash process with given
 * {@code InPut} in single call.
 */
public enum Hashes {
	/** Adler-32 checksum hash algorithm */
	Adler32(java.util.zip.Adler32::new, "Adler32"), 
	/** CRC-32 checksum hash algorithm */
	CRC32(java.util.zip.CRC32::new, "CRC32"),
	/** CRC-32C checksum hash algorithm */
	CRC32C(java.util.zip.CRC32C::new, "CRC32C"),
	
	/** MD2 message digest hash algorithm */
	MD2("MD2"),
	/** MD5 message digest hash algorithm */
	MD5("MD5"),
	
	/** SHA-1 hash algorithm */
	SHA_1("SHA-1"),

	/** SHA-224 hash algorithm */
	SHA_224("SHA-224"),
	/** SHA-256 hash algorithm */
	SHA_256("SHA-256"),
	/** SHA-384 hash algorithm */
	SHA_384("SHA-384"),
	/** SHA-512 hash algorithm */
	SHA_512("SHA-512"),
	/** SHA-512/224 hash algorithm */
	SHA_512_224("SHA-512/224"),
	/** SHA-512/256 hash algorithm */
	SHA_512_256("SHA-512/256"),
	
	/** SHA3-224 hash algorithm */
	SHA3_224("SHA3-224"),
	/** SHA3-256 hash algorithm */
	SHA3_256("SHA3-256"),
	/** SHA3-384 hash algorithm */
	SHA3_384("SHA3-384"),
	/** SHA3-512 hash algorithm */
	SHA3_512("SHA3-512");


	private Supplier<Hash> suppl;
	
	private Hashes(String messageDigestName) {
		suppl = () -> new MessageDigestHash(messageDigestName);
	}
	private Hashes(Supplier<Checksum> checksumSuppl, String name) {
		suppl = () -> new CheckSumHash(checksumSuppl.get(), name);
	}
	
	public Hash getInstance() { return suppl.get(); }
	

	
	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as a byte array.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 *
	 * @param input input data to hash
	 * @return the result of hash digest
	 */
	public byte[] toBytes(InPut input) {
		Hash h = suppl.get();
		h.reset();
		byte[] buf = new byte[8 * 1024];
		int read = 0;
		while ((read = input.getSrc(buf)) != -1) {
			h.update(buf, 0, read);
		}
		return h.doFinalToBytes();

	}

	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as {@link HexFormat hex formatted} {@code String}.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 * 
	 * 
	 * @see HexFormat 
	 * @param input input data to hash
	 * @return the result of hash digest in hex formated string
	 */
	public String toHex(InPut input) {
		return HexFormat.of().formatHex(toBytes(input));
	}

	/**
	 * Read the data from given {@code InPut}, process them and
	 * completes the hash computation.
	 * The result is returned as {@link Base64 Base64 formatted} {@code String}.
	 * The hash digest is reset before the hash process begins, and also before this method returns.
	 * 
	 * @see Base64 
	 * @param input input data to hash
	 * @return the result of hash digest in base64 formated string
	 */
	public String toBase64(InPut input) {
		return Base64.getEncoder().encodeToString(toBytes(input));
	}
}
