/*
 * Copyright (c) 2023 Eugene Hong
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.DigestException;
import java.security.MessageDigest;
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
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import io.github.awidesky.jCipher.cipher.asymmetric.AsymmetricCipherUtil;
import io.github.awidesky.jCipher.cipher.asymmetric.key.AsymmetricKeyMetadata;
import io.github.awidesky.jCipher.cipher.asymmetric.rsa.RSAKeySize;
import io.github.awidesky.jCipher.cipher.asymmetric.rsa.RSA_ECBCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.SymmetricCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AESKeySize;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_CBCCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_CTRCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_ECBCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_GCMCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.chacha20.ChaCha20KeySize;
import io.github.awidesky.jCipher.cipher.symmetric.chacha20.ChaCha20_Poly1305CipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.key.SymmetricKeyMetadata;
import io.github.awidesky.jCipher.key.keyExchange.KeyExchanger;
import io.github.awidesky.jCipher.key.keyExchange.ecdh.ECDHKeyExchanger;
import io.github.awidesky.jCipher.key.keyExchange.xdh.XDHKeyExchanger;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

@DisplayName("ALL Cipher Tests")
@Execution(ExecutionMode.CONCURRENT)
class Test {

	static final int CIPHERUTILBUFFERSIZE = 51; //odd number for test
	static final Map<String, Stream<SymmetricCipherUtil>> symmetricCiphers = Map.ofEntries(
			Map.entry("AES", Stream.of(
					new AES_GCMCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(),
					new AES_ECBCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(),
					new AES_CTRCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(),
					new AES_CTRCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(),
					new AES_CBCCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build()
				)),
			Map.entry("ChaCha20", Stream.of(
					new ChaCha20_Poly1305CipherUtil.Builder(TestUtil.password, ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(),
					new ChaCha20_Poly1305CipherUtil.Builder(TestUtil.password, ChaCha20KeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build()
				))
			);
	static final Map<String, Stream<AsymmetricCipherUtil>> asymmetricCiphers = Map.ofEntries(
			Map.entry("RSA", Stream.of(
					new RSA_ECBCipherUtil(AsymmetricKeyMetadata.with(RSAKeySize.SIZE_2048), CIPHERUTILBUFFERSIZE)
				))
			);
	static final Map<String, Stream<Supplier<KeyExchanger>>> keyExchangers = Map.ofEntries(
			Map.entry("ECDH", Stream.of(ECDHKeyExchanger::new)),
			Map.entry("XDH", Stream.of(XDHKeyExchanger::new))
			);
			

	static final Charset TESTCHARSET = Charset.forName("UTF-16"); 
	static final SecureRandom ran = new SecureRandom();
	
	static final byte[] src = new byte[101]; //odd number for test
	static final String randomStr = "random String 1234!@#$";
	
	static {
		ran.nextBytes(src);
	}
	
	@TestFactory
	@DisplayName("Test all")
	Collection<DynamicNode> testSymmetric() throws NoSuchAlgorithmException, DigestException, IOException {
		List<DynamicNode> l = new ArrayList<>(3);
		
		l.add(dynamicContainer("KeyExchangers", keyExchangers.entrySet().stream().map(entry ->  //per ECDH...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::keyExchangerTests))
		)));
		
		
		List<DynamicNode> symmetricList = new ArrayList<>();
		addSymmetricCipherKeyTests(symmetricList); //TODO : "Symmetric ciphers"안에 넣기
		symmetricList.addAll(symmetricCiphers.entrySet().stream().map(entry ->  //per AES, ChaCha20...
		dynamicContainer(entry.getKey(), entry.getValue().map(Test::symmetricCipherTests))).toList());
		l.add(dynamicContainer("Symmetric ciphers", symmetricList));
		/* TODO : fix asymmetric too
		l.add(dynamicContainer("Asymmetric ciphers", asymmetricCiphers.entrySet().stream().map(entry -> //per RSA...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::asymmetricCipherTests))
		)));
		*/
		return l;
	}
	
	private static DynamicTest getTest(CipherUtil cipher, String name, ThrowableConsumer<CipherUtil> testCode) {
		return dynamicTest(name, () -> testCode.accept(cipher));
	}
	
	private static DynamicContainer symmetricCipherTests(SymmetricCipherUtil cipher) {
		List<DynamicNode> tests = new ArrayList<>(2);
		addCommonCipherKeyTests(tests, cipher);
		return dynamicContainer(cipher.toString(), tests);
	}
	private static DynamicContainer asymmetricCipherTests(AsymmetricCipherUtil cipher) {
		List<DynamicNode> tests = new ArrayList<>(2);
		//KeyPair kp = cipher.init().keyPair(); : TODO : init cipher with keypair here
		addAsymmetricCipherKeyTests(tests, cipher);
		addCommonCipherKeyTests(tests, cipher);
		return dynamicContainer(cipher.toString(), tests);
	}
	private static DynamicContainer keyExchangerTests(Supplier<KeyExchanger> keyExchSuppl) {
		return dynamicContainer(keyExchSuppl.get().toString(), Stream.of(keyExchSuppl.get().getAvailableCurves()).map(curveName ->
			dynamicTest(curveName, () -> {
				KeyExchanger k1 = keyExchSuppl.get(); 
				KeyExchanger k2 = keyExchSuppl.get();
				
				PublicKey p1 = k1.init(curveName);
				PublicKey p2 = k2.init(curveName);
					
				SymmetricCipherUtil c1 = new AES_GCMCipherUtil.Builder(k1.exchangeKey(p2), AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build(); 
					
				SymmetricCipherUtil c2 = new AES_GCMCipherUtil.Builder(k2.exchangeKey(p1), AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build();
					
				assertEquals(TestUtil.hashPlain(src),
						TestUtil.hashPlain(c2.decryptToSingleBuffer(MessageProvider.from(c1.encryptToSingleBuffer(MessageProvider.from(src))))));
					
			})
		));
	}
	
	
	private static void addSymmetricCipherKeyTests(List<DynamicNode> list) { //TODO : how?
		list.add(dynamicTest("byte[] key test", () -> {
			byte[] key = new byte[1024];
			new Random().nextBytes(key);
			CipherUtil ci1 = new AES_GCMCipherUtil.Builder(key, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build();
			CipherUtil ci2 = new AES_GCMCipherUtil.Builder(key, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build();
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.hashPlain(ci1.decryptToSingleBuffer(MessageProvider.from(ci2.encryptToSingleBuffer(MessageProvider.from(src))))));
		}));	
		list.add(dynamicTest("password test", () -> {
			CipherUtil ci1 = new AES_GCMCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build();
			CipherUtil ci2 = new AES_GCMCipherUtil.Builder(TestUtil.password, AESKeySize.SIZE_256).bufferSize(CIPHERUTILBUFFERSIZE).keyMetadata(SymmetricKeyMetadata.DEFAULT).build();
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.hashPlain(ci1.decryptToSingleBuffer(MessageProvider.from(ci2.encryptToSingleBuffer(MessageProvider.from(src))))));
		}));	
	}
	private static void addAsymmetricCipherKeyTests(List<DynamicNode> list, AsymmetricCipherUtil cipher) {
		//TODO : signing, private나 public 하나만 주고 encrypt되는지 etc..
	}
	
	private static void addCommonCipherKeyTests(List<DynamicNode> list, CipherUtil cipher) {
		list.add(dynamicContainer("Encryption methods", Stream.of(
				getTest(cipher, "byte[] -> byte[]", (c) -> {
					assertEquals(TestUtil.hashPlain(src),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(MessageProvider.from(src))))));
							//testDecrypt(c, new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(src)))));
				}),	
				getTest(cipher, "File -> File", (c) -> {
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(new FileInputStream(fdest)))));
				}),
				getTest(cipher, "Base64 encoded String -> Base64 encoded String", (c) -> {
					String result = c.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
					assertEquals(TestUtil.hashPlain(src), TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(Base64.getDecoder().decode(result)))));
				}),
				getTest(cipher, "Hex encoded String -> Hex encoded String", (c) -> {
					String result = c.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
					assertEquals(TestUtil.hashPlain(src), TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from((HexFormat.of().parseHex(result))))));
				}),
				getTest(cipher, "String -> byte[]", (c) -> {
					assertEquals(TestUtil.hashPlain(randomStr.getBytes(TESTCHARSET)), TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(
							new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET)))))));
				}),
				getTest(cipher, "Inputstream -> Outputstream", (c) -> {
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(new FileInputStream(fdest)))));
				}),
				getTest(cipher, "part of InputStream -> byte[]", (c) -> {
					File fsrc = mkTempPlainFile();
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(
									MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 16 * 1024))))));
				}),
				getTest(cipher, "ReadableByteChannel -> WritableByteChannel", (c) -> {
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(new FileInputStream(fdest)))));
				}),
				getTest(cipher, "From part of ReadableByteChannel", (c) -> {
					File fsrc = mkTempPlainFile();
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(new ByteArrayInputStream(
									c.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 16 * 1024)))))));
				})
			)));
			final byte[] encrypted = cipher.encryptToSingleBuffer(MessageProvider.from(src));
			final String srcHash = TestUtil.hashPlain(src);
			list.add(dynamicContainer("Decryption methods", Stream.of(
				getTest(cipher, "byte[] -> byte[]", (c) -> {
					assertEquals(srcHash, TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(encrypted))));
				}),
				getTest(cipher, "File -> File", (c) -> {
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				}),
				getTest(cipher, "Base64 encoded String -> Base64 encoded String", (c) -> {
					String result = c.decryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(encrypted)));
					assertEquals(srcHash, TestUtil.hashPlain(Base64.getDecoder().decode(result)));
				}),
				getTest(cipher, "Hex encoded String -> Hex encoded String", (c) -> {
					String result = c.decryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(encrypted)));
					assertEquals(srcHash, TestUtil.hashPlain(HexFormat.of().parseHex(result)));
				}),
				getTest(cipher, "Inputstream -> Outputstream", (c) -> {
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				}),
				getTest(cipher, "ReadableByteChannel -> WritableByteChannel", (c) -> {
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				})
			)));
	}
	
	private static File mkTempPlainFile() throws IOException {
		return mkTempFile(src);
	}
	
	private static File mkTempEncryptedFile(byte[] input) throws IOException {
		return mkTempFile(input);
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


interface ThrowableConsumer<T> {
    /**
     * Performs this operation on the given argument. May throw an {@code Exception} during the opertion.
     *
     * @param t the input argument
     * @throws Exception
     */
    void accept(T t) throws Exception;
}

/*
	
	@TestFactory
	Stream<getTest> testAESGCM() {
		return Arrays.stream(ciphers).map(null);
	}
	@TestFactory
	Stream<getTest> testAESCBC() {
		return Arrays.stream(ciphers).map(null);
	}

	
	Stream<getTest> generateTests(CipherUtil c) {
		//Tests 클래스를 만들고, c를 받아서 테스트하기
		return null;
	}
*/