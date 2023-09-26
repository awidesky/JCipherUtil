/*
 * Copyright () 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import io.github.awidesky.jCipher.cipherSupplier.AsymmetricSupplier;
import io.github.awidesky.jCipher.cipherSupplier.RSA_ECBSupplier;
import io.github.awidesky.jCipherUtil.CipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipherUtil.cipher.asymmetric.rsa.RSAKeySize;
import io.github.awidesky.jCipherUtil.cipher.symmetric.SymmetricCipherUtil;
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
import io.github.awidesky.jCipherUtil.key.keyExchange.EllipticCurveKeyExchanger;
import io.github.awidesky.jCipherUtil.key.keyExchange.ecdh.ECDHKeyExchanger;
import io.github.awidesky.jCipherUtil.key.keyExchange.xdh.XDHKeyExchanger;
import io.github.awidesky.jCipherUtil.messageInterface.OutPut;
import io.github.awidesky.jCipherUtil.messageInterface.InPut;
import io.github.awidesky.jCipherUtil.util.CipherTunnel;
import io.github.awidesky.jCipherUtil.util.CipherUtilInputStream;
import io.github.awidesky.jCipherUtil.util.CipherUtilOutputStream;
import io.github.awidesky.jCipherUtil.util.UpdatableCipherOutput;
import io.github.awidesky.jCipherUtil.util.UpdatableCipherInput;

@DisplayName("ALL Cipher Tests")
@Execution(ExecutionMode.CONCURRENT)
class Test {

	static final int CIPHERUTILBUFFERSIZE = 31; //odd number for test
	static final Map<String, Stream<SymmetricCipherUtil>> symmetricCiphers = Map.ofEntries(
			Map.entry("AES", Stream.of(
					new AES_GCMCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(),
					new AES_ECBCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(),
					new AES_CTRCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(),
					new AES_CBCCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build()
				)),
			Map.entry("ChaCha20", Stream.of(
					new ChaCha20_Poly1305CipherUtil.Builder(Hash.password, ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(),
					new ChaCha20CipherUtil.Builder(Hash.password, ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build()
				))
			);
	static final Map<String, Stream<AsymmetricSupplier>> asymmetricCiphers = Map.ofEntries(
			Map.entry("RSA", Stream.of(
					new RSA_ECBSupplier(RSAKeySize.SIZE_2048, CIPHERUTILBUFFERSIZE)
				))
			);
	static final Map<String, Stream<EllipticCurveKeyExchanger[]>> keyExchangers = Map.ofEntries(
			Map.entry("ECDH", Stream.of(ECDHKeyExchanger.getAvailableCurves()).map(c -> new ECDHKeyExchanger[] {new ECDHKeyExchanger(c), new ECDHKeyExchanger(c)})),
			Map.entry("XDH", Stream.of(XDHKeyExchanger.getAvailableCurves()).map(c -> new XDHKeyExchanger[] {new XDHKeyExchanger(c), new XDHKeyExchanger(c)}))
			);
			

	static final Charset TESTCHARSET = Charset.forName("UTF-16"); 
	static final SecureRandom ran = new SecureRandom();
	
	static final byte[] src = new byte[101]; //odd number for test
	static final String randomStr = "random String 1234!@#$";
	
	static { ran.nextBytes(src); }
	
	@TestFactory
	@DisplayName("Test all")
	Collection<DynamicNode> testSymmetric() throws NoSuchAlgorithmException, DigestException, IOException {
		List<DynamicNode> l = new ArrayList<>(3);
		
		l.add(dynamicContainer("KeyExchangers", keyExchangers.entrySet().stream().map(entry ->  //per ECDH...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::keyExchangerTests))
		)));
		
		List<DynamicNode> symmetricList = new ArrayList<>();
		addSymmetricCipherKeyTests(symmetricList);
		symmetricList.addAll(symmetricCiphers.entrySet().stream().map(entry -> // per AES, ChaCha20...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::symmetricCipherTests))).toList());
		
		l.add(dynamicContainer("Symmetric ciphers", symmetricList));
		l.add(dynamicContainer("Asymmetric ciphers", asymmetricCiphers.entrySet().stream().map(entry -> // per RSA...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::asymmetricCipherTests)))));
		return l;
	}
	
	
	private static DynamicContainer symmetricCipherTests(SymmetricCipherUtil cipher) {
		List<DynamicNode> tests = new ArrayList<>();
		addCommonCipherTests(tests, cipher);
		return dynamicContainer(cipher.toString(), tests);
	}
	private static DynamicContainer asymmetricCipherTests(AsymmetricSupplier cipherSuppl) {
		List<DynamicNode> tests = new ArrayList<>();
		addAsymmetricCipherKeyTests(tests, cipherSuppl);
		addCommonCipherTests(tests, cipherSuppl.withBothKey());
		return dynamicContainer(cipherSuppl.withBothKey().toString(), tests);
	}
	private static DynamicNode keyExchangerTests(EllipticCurveKeyExchanger[] keyExchArr) {
		return dynamicTest(keyExchArr[0].getCurve(), () -> {
			EllipticCurveKeyExchanger k1 = keyExchArr[0]; 
			EllipticCurveKeyExchanger k2 = keyExchArr[1];
				
			PublicKey p1 = k1.init();
			PublicKey p2 = k2.init();
					
			SymmetricCipherUtil c1 = new AES_GCMCipherUtil.Builder(k1.exchangeKey(p2), AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build(); 
			SymmetricCipherUtil c2 = new AES_GCMCipherUtil.Builder(k2.exchangeKey(p1), AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build();
					
			assertEquals(Hash.hashPlain(src),
					Hash.hashPlain(c2.decryptToSingleBuffer(InPut.from(c1.encryptToSingleBuffer(InPut.from(src))))));
		});
	}
	
	
	private static void addSymmetricCipherKeyTests(List<DynamicNode> list) {
		list.add(dynamicTest("byte[] key test", () -> {
			byte[] key = new byte[1024];
			new Random().nextBytes(key);
			CipherUtil ci1 = new AES_ECBCipherUtil.Builder(key, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build();
			CipherUtil ci2 = new AES_ECBCipherUtil.Builder(key, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build();
			assertEquals(Hash.hashPlain(src),
					Hash.hashPlain(ci1.decryptToSingleBuffer(InPut.from(ci2.encryptToSingleBuffer(InPut.from(src))))));
		}));	
		list.add(dynamicTest("password test", () -> {
			CipherUtil ci1 = new AES_ECBCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build();
			CipherUtil ci2 = new AES_ECBCipherUtil.Builder(Hash.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(KeyMetadata.DEFAULT).build();
			assertEquals(Hash.hashPlain(src),
					Hash.hashPlain(ci1.decryptToSingleBuffer(InPut.from(ci2.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("large key value test", () -> {
			int largeKeySize = 5207;
			ByteArrayKeyMaterial bk = new ByteArrayKeyMaterial(new byte[] { 1, 2, 3, 4, 5 });
			SecretKey key =  bk.genKey("AES", largeKeySize * 8, new byte[] { 6, 7, 8, 9, 10 }, 1000);
			assertEquals(largeKeySize, key.getEncoded().length);
		}));
	}
	private static void addAsymmetricCipherKeyTests(List<DynamicNode> list, AsymmetricSupplier cipherSuppl) {
		AsymmetricCipherUtil bothKey = cipherSuppl.withBothKey();
		AsymmetricCipherUtil publicKey = cipherSuppl.withPublicOnly();
		AsymmetricCipherUtil privateKey = cipherSuppl.withPrivateOnly();
		list.add(dynamicTest("Encrypt with PublicKey only instance", () -> {
			assertEquals(Hash.hashPlain(src), Hash.hashPlain(bothKey.decryptToSingleBuffer(InPut.from(publicKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("Deccrypt with PrivateKey only instance", () -> {
			assertEquals(Hash.hashPlain(src), Hash.hashPlain(privateKey.decryptToSingleBuffer(InPut.from(bothKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
		list.add(dynamicTest("Encrypt/Deccrypt with PublicKey/PrivateKey instance", () -> {
			assertEquals(Hash.hashPlain(src), Hash.hashPlain(privateKey.decryptToSingleBuffer(InPut.from(publicKey.encryptToSingleBuffer(InPut.from(src))))));
		}));
	}
	
	private static void addCommonCipherTests(List<DynamicNode> list, CipherUtil cipher) {
		Stream.of(
				dynamicTest("CipherTunnel", () -> {
					ByteArrayOutputStream enc = new ByteArrayOutputStream();
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					CipherTunnel ct = cipher.cipherEncryptTunnel(InPut.from(src), OutPut.to(enc));
					ct.transfer();
					ct.transfer();
					ct.transferFinal();
					ct = cipher.cipherDecryptTunnel(InPut.from(enc.toByteArray()), OutPut.to(dec));
					ct.transfer();
					ct.transfer();
					ct.transferFinal();
					assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray()));
				}),	
				dynamicTest("Updatable encrypter/decrypter", () -> {
					ByteArrayOutputStream enc = new ByteArrayOutputStream();
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					UpdatableCipherInput ue = cipher.updatableInput(OutPut.to(enc), true);
					ue.update(src);
					ue.doFinal(null);
					UpdatableCipherOutput ud = cipher.updatableOutput(InPut.from(enc.toByteArray()), null);
					dec.write(ud.update());
					byte[] b = ud.doFinal();
					if(b != null) dec.write(b);
					assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray()));
				}),	
				dynamicTest("CipherUtilOutputStream <-> CipherUtilInputStream", () -> {
					File encDest = mkEmptyTempFile();
					ByteArrayOutputStream dec = new ByteArrayOutputStream();
					byte[] buf = new byte[src.length / 2];
					CipherUtilOutputStream co = new CipherUtilOutputStream(new FileOutputStream(encDest), cipher);
					CipherUtilInputStream ci = new CipherUtilInputStream(new FileInputStream(encDest), cipher);

					co.write(src[0]); co.write(src, 1, src.length - 1); co.close();
					
					dec.write(ci.read());
					int n = 0;
					while((n = ci.read(buf)) != -1) dec.write(buf, 0, n);
					assertEquals(Hash.hashPlain(src), Hash.hashPlain(dec.toByteArray()));
				}),	
				dynamicTest("byte[] <-> byte[]", () -> {
					assertEquals(Hash.hashPlain(src),
							Hash.hashPlain(cipher.decryptToSingleBuffer(InPut.from(cipher.encryptToSingleBuffer(InPut.from(src))))));
				}),	
				dynamicTest("File <-> File", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(InPut.from(fsrc), OutPut.to(encDest));
					cipher.decrypt(InPut.from(encDest), OutPut.to(decDest));
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
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
				}),
				dynamicTest("Inputstream <-> Outputstream", () -> {
					File fsrc = mkTempPlainFile();
					File encDest = mkEmptyTempFile();
					File decDest = mkEmptyTempFile();
					cipher.encrypt(InPut.from(new BufferedInputStream(new FileInputStream(fsrc))),
							OutPut.to(new BufferedOutputStream(new FileOutputStream(encDest))));
					cipher.decrypt(InPut.from(new BufferedInputStream(new FileInputStream(encDest))),
							OutPut.to(new BufferedOutputStream(new FileOutputStream(decDest))));
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of InputStream", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc), 71),
							Hash.hashPlain(cipher.decryptToSingleBuffer(InPut.from(cipher.encryptToSingleBuffer(
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
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc)), Hash.hashPlain(new FileInputStream(decDest)));
				}),
				dynamicTest("From part of ReadableByteChannel", () -> {
					File fsrc = mkTempPlainFile();
					assertEquals(Hash.hashPlain(new FileInputStream(fsrc), 71),
							Hash.hashPlain(cipher.decryptToSingleBuffer(InPut.from(new ByteArrayInputStream(
									cipher.encryptToSingleBuffer(InPut.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 71)))))));
				})
			).forEach(list::add);;
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
