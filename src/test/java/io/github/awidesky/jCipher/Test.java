/*
 * Copyright () 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import io.github.awidesky.jCipher.cipherSupplier.AsymmetricSupplier;
import io.github.awidesky.jCipher.cipherSupplier.RSA_ECBSupplier;
import io.github.awidesky.jCipher.hashCompareHelpers.ChecksumHashTestPair;
import io.github.awidesky.jCipher.hashCompareHelpers.HashTestPair;
import io.github.awidesky.jCipher.hashCompareHelpers.MessageDigestHashTestPair;
import io.github.awidesky.jCipherUtil.CipherEngine;
import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.key.KeyPairMaterial;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa.RSAKeySize;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtilBuilder;
import io.github.awidesky.jCipherUtil.cipher.symmetric.aes.AESKeySize;
import io.github.awidesky.jCipherUtil.cipher.symmetric.aes.AES_CBCCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.aes.AES_CTRCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.aes.AES_ECBCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.aes.AES_GCMCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20.ChaCha20CipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20.ChaCha20KeySize;
import io.github.awidesky.jCipherUtil.cipher.symmetric.chacha20.ChaCha20_Poly1305CipherUtil;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.ByteArrayKeyMaterial;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.KeyMetadata;
import io.github.awidesky.jCipherUtil.cipher.symmetric.key.PasswordKeyMaterial;
import io.github.awidesky.jCipherUtil.exceptions.OmittedCipherException;
import io.github.awidesky.jCipherUtil.hash.Hash;
import io.github.awidesky.jCipherUtil.hash.checksum.Adler32Hash;
import io.github.awidesky.jCipherUtil.hash.checksum.CRC32CHash;
import io.github.awidesky.jCipherUtil.hash.checksum.CRC32Hash;
import io.github.awidesky.jCipherUtil.hash.checksum.CheckSumHash;
import io.github.awidesky.jCipherUtil.hash.messageDigest.MD2;
import io.github.awidesky.jCipherUtil.hash.messageDigest.MD5;
import io.github.awidesky.jCipherUtil.hash.messageDigest.SHA_1;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha3.SHA3_224;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha3.SHA3_256;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha3.SHA3_384;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha3.SHA3_512;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha_2.SHA_224;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha_2.SHA_256;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha_2.SHA_384;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha_2.SHA_512_224;
import io.github.awidesky.jCipherUtil.hash.messageDigest.sha_2.SHA_512_256;
import io.github.awidesky.jCipherUtil.key.KeySize;
import io.github.awidesky.jCipherUtil.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipherUtil.key.keyExchange.ecdh.ECDHCurves;
import io.github.awidesky.jCipherUtil.key.keyExchange.ecdh.ECDHKeyExchanger;
import io.github.awidesky.jCipherUtil.key.keyExchange.xdh.XDHCurves;
import io.github.awidesky.jCipherUtil.key.keyExchange.xdh.XDHKeyExchanger;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.util.CipherMode;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.CipherUtilInputStream;
import io.github.awidesky.jCipherUtil.util.CipherUtilOutputStream;

@DisplayName("ALL Cipher Tests")
@Execution(ExecutionMode.CONCURRENT)
class Test {

	static final int CIPHERUTILBUFFERSIZE = 31; //odd number for test
	static final Map<String, Stream<SymmetricCipherUtilBuilder<? extends SymmetricCipherUtil>>> symmetricCiphers = Map.ofEntries(
			Map.entry("AES", Stream.of(
					new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT),
					new AES_ECBCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT),
					new AES_CTRCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT),
					new AES_CBCCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT)
				)),
			Map.entry("ChaCha20", Stream.of(
					new ChaCha20_Poly1305CipherUtil.Builder(ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT),
					new ChaCha20CipherUtil.Builder(ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT)
				))
			);
	static final Map<String, Stream<AsymmetricSupplier>> asymmetricCiphers = Map.ofEntries(
			Map.entry("RSA", Stream.of(
					new RSA_ECBSupplier(RSAKeySize.SIZE_2048, CIPHERUTILBUFFERSIZE)
				))
			);
	static final Map<String, Stream<EllipticCurveKeyExchanger[]>> keyExchangers = Map.ofEntries(
			Map.entry("ECDH", Stream.of(ECDHKeyExchanger.getAvailableCurves()).map(ECDHCurves::valueOf).map(c -> new ECDHKeyExchanger[] {new ECDHKeyExchanger(c), new ECDHKeyExchanger(c)})),
			Map.entry("XDH", Stream.of(XDHKeyExchanger.getAvailableCurves()).map(XDHCurves::valueOf).map(c -> new XDHKeyExchanger[] {new XDHKeyExchanger(c), new XDHKeyExchanger(c)}))
			);
			
	static final Map<String, Stream<? extends MessageDigestHashTestPair>> messageDigestHashes = Map.ofEntries(
			Map.entry("SHA1", Stream.of(new MessageDigestHashTestPair(SHA_1::new))),
			Map.entry("SHA2", Stream.of(new MessageDigestHashTestPair(SHA_224::new), new MessageDigestHashTestPair(SHA_256::new), new MessageDigestHashTestPair(SHA_384::new), new MessageDigestHashTestPair(SHA_512_224::new), new MessageDigestHashTestPair(SHA_512_256::new))),
			Map.entry("SHA3", Stream.of(new MessageDigestHashTestPair(SHA3_224::new), new MessageDigestHashTestPair(SHA3_256::new), new MessageDigestHashTestPair(SHA3_384::new), new MessageDigestHashTestPair(SHA3_512::new))),
			Map.entry("MD", Stream.of(new MessageDigestHashTestPair(MD2::new), new MessageDigestHashTestPair(MD5::new)))
			);
	static final Map<String, Stream<? extends ChecksumHashTestPair>> checksumHashes = Map.ofEntries(
			Map.entry("Adler", Stream.of(new ChecksumHashTestPair(Adler32Hash::new, new Adler32()))),
			Map.entry("CRC", Stream.of(new ChecksumHashTestPair(CRC32Hash::new, new CRC32()), new ChecksumHashTestPair(CRC32CHash::new, new CRC32C())))
			);
	

	static final Charset TESTCHARSET = Charset.forName("UTF-16"); 
	static final SecureRandom ran = new SecureRandom();
	
	static final byte[] src = new byte[101]; //odd number for test
	static final String randomStr = "random String 1234!@#$";
	
	static { ran.nextBytes(src); }
	
	@TestFactory
	@DisplayName("Test all")
	Collection<DynamicNode> testAll() throws NoSuchAlgorithmException, DigestException, IOException {
		List<DynamicNode> l = new ArrayList<>(3);
		
		List<DynamicNode> keyExList = new ArrayList<DynamicNode>();
		keyExList.add(dynamicTest("default curves", () -> {
			assertEquals(new ECDHKeyExchanger().getCurve(), ECDHCurves.secp521r1.name(), "ECDH key exchanger default curve test : ");
			assertEquals(new XDHKeyExchanger().getCurve(), XDHCurves.X25519.name(), "XDH key exchanger default curve test : ");
		}));
		keyExList.addAll(keyExchangers.entrySet().stream().map(entry ->  //per ECDH...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::keyExchangerTests))
		).toList());
		l.add(dynamicContainer("KeyExchangers", keyExList));
		
		List<DynamicNode> symmetricList = new ArrayList<>();
		symmetricList.add(dynamicTest("large key size test", () -> {
			int largeKeySize = 5207;
			ByteArrayKeyMaterial bk = new ByteArrayKeyMaterial(new byte[] { 1, 2, 3, 4, 5 });
			SecretKey key =  bk.genKey("AES", largeKeySize * 8, new byte[] { 6, 7, 8, 9, 10 }, 1000);
			assertEquals(largeKeySize, key.getEncoded().length);
		}));
		symmetricList.addAll(symmetricCiphers.entrySet().stream().map(entry -> // per AES, ChaCha20...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::symmetricCipherTests))).toList());
		symmetricList.add(symmetricAdditionalTests());
		
		
		l.add(dynamicContainer("Symmetric ciphers", symmetricList));
		l.add(dynamicContainer("Asymmetric ciphers", asymmetricCiphers.entrySet().stream().map(entry -> // per RSA...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::asymmetricCipherTests)))));
		

		LinkedList<DynamicContainer> hashTests = new LinkedList<>();
		messageDigestHashes.entrySet().stream().map(entry -> dynamicContainer(entry.getKey(), entry.getValue().map(Test::addHashTests))).forEach(hashTests::add);
		checksumHashes.entrySet().stream().map(entry -> dynamicContainer(entry.getKey(), entry.getValue().map(Test::addHashTests))).forEach(hashTests::add);
		l.add(dynamicContainer("Hash", hashTests));
		
		return l;
	}
	

	private static DynamicNode keyExchangerTests(EllipticCurveKeyExchanger[] keyExchArr) {
		return dynamicTest(keyExchArr[0].toString(), () -> {
			EllipticCurveKeyExchanger k1 = keyExchArr[0]; 
			EllipticCurveKeyExchanger k2 = keyExchArr[1];
				
			PublicKey p1 = k1.init();
			PublicKey p2 = k2.init();
					
			SymmetricCipherUtil c1 = new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(k1.exchangeKey(p2)); 
			SymmetricCipherUtil c2 = new AES_GCMCipherUtil.Builder(AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(k2.exchangeKey(p1));
					
			assertEquals(HashHelper.hashPlain(src),
					HashHelper.hashPlain(c2.decryptToSingleBuffer(InPut.from(c1.encryptToSingleBuffer(InPut.from(src))))));
		});
	}
	
	
	private static DynamicContainer symmetricCipherTests(SymmetricCipherUtilBuilder<? extends SymmetricCipherUtil> cipherBuilder) {
		List<DynamicNode> tests = new ArrayList<>();
		addSymmetricCipherKeyTests(tests, cipherBuilder);
		SymmetricCipherUtil cipher = cipherBuilder.build(HashHelper.password);
		addCommonCipherTests(tests, cipher);
		tests.add(dynamicTest("CipherUtilInputStream large input test", () -> {
			/*
			 * Test if inner buffer (outputBuffer) of CipherUtilInputStream works well with large inputs,
			 * where the output of inner CipherEngine is larger than remaining of outputBuffer.
			 * */
			byte[] hugeData = new byte[CipherUtilInputStream.DEFAULT_BUFFER_SIZE + 1024];
			new Random().nextBytes(hugeData);
			
			CipherUtilInputStream ciEnc = cipher.inputStream(new ByteArrayInputStream(hugeData), CipherMode.ENCRYPT_MODE);
			ByteArrayOutputStream enc = new ByteArrayOutputStream();
			enc.write(ciEnc.read());
			int n = 0;
			byte[] buf = new byte[CipherUtilInputStream.DEFAULT_BUFFER_SIZE];
			while((n = ciEnc.read(buf)) != -1) enc.write(buf, 0, n);
			ciEnc.close();
			CipherUtilInputStream ciDec = cipher.inputStream(new ByteArrayInputStream(enc.toByteArray()), CipherMode.DECRYPT_MODE);
			ByteArrayOutputStream dec = new ByteArrayOutputStream();
			dec.write(ciDec.read());
			n = 0;
			while((n = ciDec.read(buf)) != -1) dec.write(buf, 0, n);
			ciDec.close();
			assertEquals(HashHelper.hashPlain(hugeData), HashHelper.hashPlain(dec.toByteArray()));
		}));
		return dynamicContainer(cipher.toString(), tests);
	}
	private static DynamicContainer asymmetricCipherTests(AsymmetricSupplier cipherSuppl) {
		List<DynamicNode> tests = new ArrayList<>();
		addAsymmetricCipherKeyTests(tests, cipherSuppl);
		addCommonCipherTests(tests, cipherSuppl.withBothKey());
		return dynamicContainer(cipherSuppl.withBothKey().toString(), tests);
	}
	

	private DynamicContainer symmetricAdditionalTests() {
		return dynamicContainer("additional tests", Stream.of(
				dynamicTest("AES_CTR counter bound", () -> {
					assertThrows(IllegalArgumentException.class,
							() -> { new AES_CTRCipherUtil.Builder(AESKeySize.SIZE_256).counterLen(256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(HashHelper.password);});
					assertThrows(IllegalArgumentException.class,
							() -> { new AES_CTRCipherUtil.Builder(AESKeySize.SIZE_256, -256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(HashHelper.password);});
				})));
	}

	
	private static void addSymmetricCipherKeyTests(List<DynamicNode> list, SymmetricCipherUtilBuilder<? extends SymmetricCipherUtil> cipherBuilder) {
		list.add(dynamicTest("byte[] key test", () -> {
			byte[] key = new byte[1024];
			new Random().nextBytes(key);
			CipherUtil ci1 = cipherBuilder.build(key);
			CipherUtil ci2 = cipherBuilder.build(key);
			assertEquals(HashHelper.hashPlain(src),
					HashHelper.hashPlain(ci1.decryptToSingleBuffer(InPut.from(ci2.encryptToSingleBuffer(InPut.from(src))))));
		}));	
		list.add(dynamicTest("password test", () -> {
			CipherUtil ci1 = cipherBuilder.build(HashHelper.password);
			CipherUtil ci2 = cipherBuilder.build(HashHelper.password);
			assertEquals(HashHelper.hashPlain(src),
					HashHelper.hashPlain(ci1.decryptToSingleBuffer(InPut.from(ci2.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("invalid key size test", () -> {
			int smallKeySize = 12;
			int largeKeySize = 264;
			int originalKeySize = cipherBuilder.build(HashHelper.password).keySize();
			SymmetricCipherUtil c1 = cipherBuilder.keySize(new KeySize(smallKeySize)).build(HashHelper.password);
			SymmetricCipherUtil c2 = cipherBuilder.keySize(new KeySize(largeKeySize)).build(HashHelper.password);
			cipherBuilder.keySize(new KeySize(originalKeySize));
			assertThrows(OmittedCipherException.class,
					() -> c1.encryptToSingleBuffer(InPut.from(src)));
			assertThrows(OmittedCipherException.class,
					() -> c2.encryptToSingleBuffer(InPut.from(src)));
		}));
		list.add(dynamicTest("key material destroy test", () -> {
			PasswordKeyMaterial p = new PasswordKeyMaterial(HashHelper.password);
			ByteArrayKeyMaterial b = new ByteArrayKeyMaterial(src);
			char[] prev1 = p.getPassword();
			byte[] prev2 = b.getKeySource();
			p.destroy(); b.destroy();
			assertEquals(true, p.isDestroyed(), "PasswordKeyMaterial is not destroyed");
			assertEquals(true, b.isDestroyed(), "ByteArrayKeyMaterial is not destroyed");
			assertNotEquals(prev1, p.getPassword(), "PasswordKeyMaterial data is not deleted");
			assertNotEquals(prev2, b.getKeySource(), "ByteArrayKeyMaterial data is not deleted");
			String keyAlgo = cipherBuilder.build(HashHelper.password).getCipherProperty().KEY_ALGORITMH_NAME;
			assertThrows(IllegalStateException.class, () -> p.genKey(keyAlgo, 256, src, 100));
			assertThrows(IllegalStateException.class, () -> b.genKey(keyAlgo, 256, src, 100));
			SymmetricCipherUtil c1 = cipherBuilder.build(HashHelper.password);
			c1.destroyKey();
			assertThrows(IllegalStateException.class, () -> c1.encryptToSingleBuffer(InPut.from(src)));
			SymmetricCipherUtil c2 = cipherBuilder.build(src); c2.destroyKey();
			assertThrows(IllegalStateException.class, () -> c2.encryptToSingleBuffer(InPut.from(src)));
		}));
	}
	private static void addAsymmetricCipherKeyTests(List<DynamicNode> list, AsymmetricSupplier cipherSuppl) {
		AsymmetricCipherUtil bothKey = cipherSuppl.withBothKey();
		AsymmetricCipherUtil publicKey = cipherSuppl.withPublicOnly();
		AsymmetricCipherUtil privateKey = cipherSuppl.withPrivateOnly();
		list.add(dynamicTest("Encrypt with PublicKey only instance", () -> {
			assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(bothKey.decryptToSingleBuffer(InPut.from(publicKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("Decrypt with PrivateKey only instance", () -> {
			assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(privateKey.decryptToSingleBuffer(InPut.from(bothKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("Encrypt/Decrypt with PublicKey/PrivateKey instance", () -> {
			assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(privateKey.decryptToSingleBuffer(InPut.from(publicKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("public/private key size", () -> {
			assertEquals(publicKey.publicKeyLength(), privateKey.privateKeyLength());
			assertEquals(-1, publicKey.privateKeyLength());
			assertEquals(-1, privateKey.publicKeyLength());
		}));
		list.add(dynamicTest("key material destroy test", () -> {
			KeyPairMaterial kp = new KeyPairMaterial(cipherSuppl.withBothKey().generateKeyPair(new KeySize(2048)));
			Encoder base64Encoder = Base64.getEncoder();
			KeyPairMaterial kp2 = new KeyPairMaterial(base64Encoder .encodeToString(kp.getEncodedPublic()), base64Encoder.encodeToString(kp.getEncodedPrivate()));
			kp.destroy();
			assertEquals(true, kp.isDestroyed(), "KeyPairMaterial is not destroyed");
			assertNotEquals(kp2.getEncodedPublic(), kp.getEncodedPublic(), "PublicKeyMaterial data is not deleted");
			assertNotEquals(kp2.getEncodedPrivate(), kp.getEncodedPrivate(), "PrivateKeyMaterial data is not deleted");
			AsymmetricCipherUtil c1 = cipherSuppl.withBothKey(); c1.destroyKey();
			assertThrows(IllegalStateException.class, () -> c1.encryptToSingleBuffer(InPut.from(src)));
			AsymmetricCipherUtil c2 = cipherSuppl.withBothKey(); c2.destroyKey();
			assertThrows(IllegalStateException.class, () -> c2.encryptToSingleBuffer(InPut.from(src)));
		}));
	}
	
	private static void addCommonCipherTests(List<DynamicNode> list, CipherUtil cipher) {
		Stream.of(
				dynamicTest("CipherTunnel", () -> {
					ByteArrayOutputStream enc = new ByteArrayOutputStream();
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					CipherTunnel ct = cipher.cipherTunnel(InPut.from(src), OutPut.to(enc), CipherMode.ENCRYPT_MODE);
					ct.transfer();
					ct.transfer();
					ct.transferFinal();
					assertEquals(-1, ct.transfer()); assertEquals(-1, ct.transferFinal()); assertTrue(ct.isFinished());
					ct = cipher.cipherTunnel(InPut.from(enc.toByteArray()), OutPut.to(dec), CipherMode.DECRYPT_MODE);
					ct.transfer();
					ct.transfer();
					ct.transferFinal();
					assertEquals(-1, ct.transfer()); assertEquals(-1, ct.transferFinal()); assertTrue(ct.isFinished());
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(dec.toByteArray()));
				}),
				dynamicTest("CipherEngine", () -> {
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					CipherEngine ue = cipher.cipherEngine(CipherMode.ENCRYPT_MODE);
					CipherEngine ud = cipher.cipherEngine(CipherMode.DECRYPT_MODE);
					assertEquals(CipherMode.ENCRYPT_MODE, ue.mode());
					assertEquals(CipherMode.DECRYPT_MODE, ud.mode());
					dec.write(ud.update(ue.update(src)));
					dec.write(ud.doFinal(ue.doFinal()));
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(dec.toByteArray()));
					assertEquals(ud.isFinished(), true); assertEquals(ue.isFinished(), true);
					assertEquals(null, ud.update(new byte[4])); assertEquals(null, ud.doFinal()); assertEquals(null, ud.doFinal(new byte[4]));
					assertEquals(null, ue.update(new byte[4])); assertEquals(null, ue.doFinal()); assertEquals(null, ue.doFinal(new byte[4]));
				}),
				dynamicTest("CipherUtilInputStream(Encryption)", () -> {
					File plain = mkTempPlainFile();
					CipherUtilInputStream ci = cipher.inputStream(new FileInputStream(plain), CipherMode.ENCRYPT_MODE);
					assertEquals(CipherMode.ENCRYPT_MODE, ci.mode()); assertFalse(ci.markSupported());
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					dec.write(ci.read());
					int n = 0;
					byte[] buf = new byte[src.length / 2];
					while((n = ci.read(buf)) != -1) dec.write(buf, 0, n);
					ci.close();
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(cipher.decryptToSingleBuffer(InPut.from(dec.toByteArray()))));
					assertEquals(-1, ci.read());
					/* CipherUtilInputStream Exception test */
					CipherUtilInputStream temp = cipher.inputStream(new FileInputStream(plain), CipherMode.ENCRYPT_MODE);
					assertThrows(IOException.class, () -> { temp.close(); } );
					temp.abort(); assertDoesNotThrow(() -> { temp.close(); } );
				}),
				dynamicTest("CipherUtilInputStream(Decryption)", () -> {
					File enc = mkTempFile(cipher.encryptToSingleBuffer(InPut.from(src)));
					CipherUtilInputStream ci = cipher.inputStream(new FileInputStream(enc), CipherMode.DECRYPT_MODE);
					assertEquals(CipherMode.DECRYPT_MODE, ci.mode()); assertFalse(ci.markSupported());
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					dec.write(ci.read());
					int n = 0;
					byte[] buf = new byte[src.length / 2];
					while((n = ci.read(buf)) != -1) dec.write(buf, 0, n);
					ci.close();
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(dec.toByteArray()));
					assertEquals(-1, ci.read(), "CipherUtilInputStream.read() does not return -1 after closed!");
					/* CipherUtilInputStream Exception test */
					CipherUtilInputStream temp = cipher.inputStream(new FileInputStream(enc), CipherMode.DECRYPT_MODE);
					assertThrows(IOException.class, () -> { temp.close(); } );
					temp.abort(); assertDoesNotThrow(() -> { temp.close(); } );
				}),	
				dynamicTest("CipherUtilOutputStream(Encryption)", () -> {
					ByteArrayOutputStream enc = new ByteArrayOutputStream();
					CipherUtilOutputStream co = cipher.outputStream(enc, CipherMode.ENCRYPT_MODE);
					assertEquals(CipherMode.ENCRYPT_MODE, co.mode());
					co.write(src[0]); co.write(src, 1, src.length - 1); co.close();
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(cipher.decryptToSingleBuffer(InPut.from(enc.toByteArray()))));
					co.close(); assertThrows(IOException.class, () -> { co.write(new byte[4]); } );
				}),
				dynamicTest("CipherUtilOutputStream(Decryption)", () -> {
					byte[] enc = cipher.encryptToSingleBuffer(InPut.from(src));
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					CipherUtilOutputStream co = cipher.outputStream(dec, CipherMode.DECRYPT_MODE);
					assertEquals(CipherMode.DECRYPT_MODE, co.mode());
					co.write(enc[0]); co.write(enc, 1, enc.length - 1); co.close();
					assertEquals(HashHelper.hashPlain(src), HashHelper.hashPlain(dec.toByteArray()));
					co.close(); assertThrows(IOException.class, () -> { co.write(new byte[4]); } );
				}),
				dynamicTest("byte[] <-> byte[]", () -> {
					assertEquals(HashHelper.hashPlain(src),
							HashHelper.hashPlain(cipher.decryptToSingleBuffer(InPut.from(cipher.encryptToSingleBuffer(InPut.from(src))))));
				}),	
				dynamicTest("File <-> File", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(InPut.from(fsrc), OutPut.to(encDest));
					cipher.decrypt(InPut.from(encDest), OutPut.to(decDest));
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc)), HashHelper.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("Path <-> Path", () -> {
					Path psrc = mkTempPlainFile().toPath();
					Path encDest = mkEmptyTempFile().toPath();
					Path decDest = mkEmptyTempFile().toPath();
					cipher.encrypt(InPut.from(psrc), OutPut.to(encDest));
					cipher.decrypt(InPut.from(encDest), OutPut.to(decDest));
					assertEquals(HashHelper.hashPlain(new FileInputStream(psrc.toFile())), HashHelper.hashPlain(new FileInputStream(decDest.toFile())));
				}),
				dynamicTest("Base64 encoded String <-> Base64 encoded String", () -> {
					String encrypted = cipher.encryptToBase64(InPut.fromBase64(Base64.getEncoder().encodeToString(src)));
					String decrypted = cipher.decryptToBase64(InPut.fromBase64(encrypted));
					assertEquals(Base64.getEncoder().encodeToString(src), decrypted);
				}),
				dynamicTest("Hex encoded String <-> Hex encoded String", () -> {
					String encrypted = cipher.encryptToHexString(InPut.fromHexString(HexFormat.of().formatHex(src)));
					String decrypted = cipher.decryptToHexString(InPut.fromHexString(encrypted));
					assertEquals(HexFormat.of().formatHex(src), decrypted);
				}),
				dynamicTest("String <-> String", () -> {
					assertEquals(randomStr, cipher.decryptToString(InPut.from(
							cipher.encryptToSingleBuffer(InPut.from(randomStr, TESTCHARSET))), TESTCHARSET));
					assertEquals(randomStr, cipher.decryptToString(InPut.from(
							cipher.encryptToSingleBuffer(InPut.from(randomStr))), Charset.defaultCharset()),
							"Default charset in InPut.from(String) is not " + Charset.defaultCharset().name());
				}),
				dynamicTest("Inputstream <-> Outputstream", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(new BufferedInputStream(new FileInputStream(fsrc)),
							new BufferedOutputStream(new FileOutputStream(encDest)));
					cipher.decrypt(new BufferedInputStream(new FileInputStream(encDest)),
							new BufferedOutputStream(new FileOutputStream(decDest)));
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc)), HashHelper.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("Inputstream <-> Outputstream through InPut/Output", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(InPut.from(new BufferedInputStream(new FileInputStream(fsrc))),
							OutPut.to(new BufferedOutputStream(new FileOutputStream(encDest))));
					cipher.decrypt(InPut.from(new BufferedInputStream(new FileInputStream(encDest))),
							OutPut.to(new BufferedOutputStream(new FileOutputStream(decDest))));
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc)), HashHelper.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of InputStream", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc), 71),
							HashHelper.hashPlain(cipher.decryptToSingleBuffer(InPut.from(cipher.encryptToSingleBuffer(
									InPut.from(new BufferedInputStream(new FileInputStream(fsrc)), 71))))));
				}),
				dynamicTest("ReadableByteChannel <-> WritableByteChannel", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(InPut.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							OutPut.to(FileChannel.open(encDest.toPath(), StandardOpenOption.WRITE)));
					cipher.decrypt(InPut.from(FileChannel.open(encDest.toPath(), StandardOpenOption.READ)),
							OutPut.to(FileChannel.open(decDest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc)), HashHelper.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of ReadableByteChannel", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(HashHelper.hashPlain(new FileInputStream(fsrc), 71),
							HashHelper.hashPlain(cipher.decryptToSingleBuffer(InPut.from(new ByteArrayInputStream(
									cipher.encryptToSingleBuffer(InPut.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 71)))))));
				})
			).forEach(list::add);;
	}

	private static DynamicContainer addHashTests(HashTestPair hashPair) {
		LinkedList<DynamicNode> tests = new LinkedList<>();
		Stream.of(
			dynamicTest("partial hashing vs whole hashing", () -> {
				Hash h = hashPair.getHash();
				h.update(src, 0, src.length / 2);
				h.update(src, src.length / 2, src.length - src.length / 2);
				byte[] bytesPart = h.doFinalhToBytes();
				byte[] bytesWhole = h.doFinalToBytes(src);
				byte[] bytesInput = h.toBytes(InPut.from(mkTempPlainFile()));
				
				assertArrayEquals(bytesPart, bytesWhole, "partial update result is not matched with one-time finish result!");
				assertArrayEquals(bytesWhole, bytesInput, "partial update result is not matched with one-time finish result!(Hash.toBytes)");
			}),
			dynamicTest("compare from Java library results", () -> {
				Hash h = hashPair.getHash();
				byte[] bytesWhole = h.doFinalToBytes(src);
				byte[] cmp = hashPair.getCmp().hash(src);
				
				assertArrayEquals(cmp, bytesWhole, "the result differes from one calculated from JDK classes!");
			}),
			dynamicTest("Base64 output format", () -> {
				Hash h = hashPair.getHash();
				byte[] bytesPart = h.doFinalToBytes(src);
				String base64_1 = h.doFinalToBase64(src);
				String base64_2 = h.toBase64(InPut.from(mkTempPlainFile()));
				
				assertArrayEquals(bytesPart, Base64.getDecoder().decode(base64_1), "Base64 result not matching!");
				assertArrayEquals(bytesPart, Base64.getDecoder().decode(base64_2), "Base64 result not matching!(Hash.toBase64)");
			}),
			dynamicTest("Hex output format", () -> {
				Hash h = hashPair.getHash();
				byte[] bytesPart = h.doFinalToBytes(src);
				String hex_1 = h.doFinalToHex(src);
				String hex_2 = h.toHex(InPut.from(mkTempPlainFile()));
				
				assertArrayEquals(bytesPart, HexFormat.of().parseHex(hex_1), "Hex format result not matching!");
				assertArrayEquals(bytesPart, HexFormat.of().parseHex(hex_2), "Hex format result not matching!(Hash.toHex)");
			})
		).forEach(tests::add);
		
		if (hashPair instanceof ChecksumHashTestPair chtp) {
			Stream.of(
				dynamicTest("partial hashing vs whole hashing in type long", () -> {
					CheckSumHash h = chtp.getHash();
					h.update(src, 0, src.length / 2);
					h.update(src, src.length / 2, src.length - src.length / 2);
					long longPart = h.finishToLong();
					long longWhole = h.finishToLong(src);
					long longInput = h.toLong(InPut.from(src));
						
					assertEquals(longPart, longWhole, "partial update result is not matched with one-time finish result!");
					assertEquals(longWhole, longInput, "partial update result is not matched with one-time finish result!(CheckSumHash.toLong)");
				}),
				dynamicTest("byte[] to long conversion", () -> {
					CheckSumHash h = chtp.getHash();
					long longWhole = h.finishToLong(src);
						
					assertEquals(longWhole, ByteBuffer.wrap(h.doFinalToBytes(src)).order(ByteOrder.BIG_ENDIAN).getLong(),
							"the long result is erroneously converted to byte[]!");
				}),
				dynamicTest("compare from Java library results", () -> {
					CheckSumHash h = chtp.getHash();
					long longWhole = h.finishToLong(src);
					long cmp = chtp.getCmp().hashLong(src);

					assertEquals(cmp, longWhole, "the result differes from one calculated from Java library!");
				})
			).forEach(tests::add);
		}
		
		return dynamicContainer(hashPair.getHash().getName(), tests);
	}
	
	
	private static File mkTempPlainFile() throws IOException {
		return mkTempFile(src);
	}
	
	private static File mkTempFile(byte[] data) throws IOException {
		File f = Files.createTempFile("CipherUtilTestSrc", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(f));
		bo.write(data);
		bo.close();
		return f;
	}
	private static File mkEmptyTempFile() throws IOException {
		File f = Files.createTempFile("CipherUtilTestEmpty", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		return f;
	}
}
