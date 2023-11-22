package io.github.awidesky.jCipher.hashCompareHelpers;

import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;

import io.github.awidesky.jCipherUtil.hash.Hashes;

public class HashComparartorGenerator {

	public static HashComparator generate(Hashes hash) {
		switch (hash) {
		case Adler32:
			return new ChecksumComparator(new Adler32());
		case CRC32:
			return new ChecksumComparator(new CRC32());
		case CRC32C:
			return new ChecksumComparator(new CRC32C());
		default:
			return new MessageDigestComparator(hash.getInstance().getName());
			
		}
	}
}
