package io.github.awidesky.jCipherUtil.hash;

import java.util.function.Supplier;
import java.util.zip.Checksum;

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
}
