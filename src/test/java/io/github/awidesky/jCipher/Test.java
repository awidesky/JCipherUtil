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
import java.security.KeyPair;
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
import java.util.function.Consumer;
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
import io.github.awidesky.jCipher.cipher.asymmetric.keyExchange.KeyExchanger;
import io.github.awidesky.jCipher.cipher.asymmetric.keyExchange.ECDH.ECDHKeyExchanger;
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
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;

@DisplayName("ALL Cipher Tests")
@Execution(ExecutionMode.CONCURRENT)
class Test {

	static final int CIPHERUTILBUFFERSIZE = 51; //odd number for test
	static final Map<String, Stream<Supplier<SymmetricCipherUtil>>> symmetricCiphers = Map.ofEntries(
			Map.entry("AES", Stream.of(
					() -> new AES_GCMCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_ECBCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_CTRCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_CBCCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE)
				)),
			Map.entry("ChaCha20", Stream.of(
					() -> new ChaCha20_Poly1305CipherUtil(SymmetricKeyMetadata.DEFAULT.with(ChaCha20KeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new ChaCha20_Poly1305CipherUtil(SymmetricKeyMetadata.DEFAULT.with(ChaCha20KeySize.SIZE_256), CIPHERUTILBUFFERSIZE)
				))
			);
	static final Map<String, Stream<Supplier<AsymmetricCipherUtil>>> asymmetricCiphers = Map.ofEntries(
			Map.entry("RSA", Stream.of(
					() -> new RSA_ECBCipherUtil(AsymmetricKeyMetadata.with(RSAKeySize.SIZE_2048), CIPHERUTILBUFFERSIZE)
				))
			);
	static final Map<String, Stream<Supplier<KeyExchanger>>> keyExchangers = Map.ofEntries(
			Map.entry("ECDH", Stream.of(ECDHKeyExchanger::new))
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
		
		l.add(dynamicContainer("Symmetric ciphers", symmetricCiphers.entrySet().stream().map(entry ->  //per AES, ChaCha20...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::symmetricCipherTests))
		)));
	
		l.add(dynamicContainer("Asymmetric ciphers", asymmetricCiphers.entrySet().stream().map(entry -> //per RSA...
			dynamicContainer(entry.getKey(), entry.getValue().map(Test::asymmetricCipherTests))
		)));
		
		return l;
	}
	
	private static DynamicTest getTest(Supplier<? extends CipherUtil> cipherSuppl, String name, ThrowableConsumer<CipherUtil> testCode) {
		return dynamicTest(name, () -> testCode.accept(cipherSuppl.get()));
	}
	
	private static DynamicContainer symmetricCipherTests(Supplier<SymmetricCipherUtil> cipherSuppl) {
		List<DynamicNode> tests = new ArrayList<>(4);
		addSymmetricCipherKeyTests(tests, cipherSuppl);
		addCommonCipherKeyTests(tests, cipherSuppl, c -> ((SymmetricCipherUtil) c).init(TestUtil.password));
		return dynamicContainer(cipherSuppl.get().toString(), tests);
	}
	private static DynamicContainer asymmetricCipherTests(Supplier<AsymmetricCipherUtil> cipherSuppl) {
		List<DynamicNode> tests = new ArrayList<>(2);
		KeyPair kp = cipherSuppl.get().init().keyPair();
		addAsymmetricCipherKeyTests(tests, cipherSuppl);
		addCommonCipherKeyTests(tests, cipherSuppl, c -> ((AsymmetricCipherUtil) c).init(kp));
		return dynamicContainer(cipherSuppl.get().toString(), tests);
	}
	private static DynamicTest keyExchangerTests(Supplier<KeyExchanger> keyExchSuppl) {
		return dynamicTest(keyExchSuppl.get().toString(), () -> { //TODO : test for all curves?
			KeyExchanger k1 = keyExchSuppl.get(); 
			KeyExchanger k2 = keyExchSuppl.get();
			
			PublicKey p1 = k1.init();
			PublicKey p2 = k2.init();
			
			SymmetricCipherUtil c1 = new AES_GCMCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE);
			c1.init(k1.exchangeKey(p2));
			
			SymmetricCipherUtil c2 = new AES_GCMCipherUtil(SymmetricKeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE);
			c2.init(k2.exchangeKey(p1));
			
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.hashPlain(c2.decryptToSingleBuffer(MessageProvider.from(c1.encryptToSingleBuffer(MessageProvider.from(src))))));
			
		});
	}
	
	
	private static void addSymmetricCipherKeyTests(List<DynamicNode> list, Supplier<SymmetricCipherUtil> cipherSuppl) {
		list.add(dynamicTest("byte[] key test", () -> {
			SymmetricCipherUtil c = cipherSuppl.get();
			byte[] key = new byte[1024];
			new Random().nextBytes(key);
			c.init(key);
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(MessageProvider.from(src))))));
		}));	
		list.add(dynamicTest("password test", () -> {
			SymmetricCipherUtil c = cipherSuppl.get();
			c.init(TestUtil.password);
			assertEquals(TestUtil.hashPlain(src),
					TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(MessageProvider.from(src))))));
		}));	
	}
	private static void addAsymmetricCipherKeyTests(List<DynamicNode> list, Supplier<AsymmetricCipherUtil> cipherSuppl) {
		//TODO : signing, private나 public 하나만 주고 encrypt되는지 etc..
	}
	
	private static void addCommonCipherKeyTests(List<DynamicNode> list, Supplier<? extends CipherUtil> cipherSuppl, Consumer<CipherUtil> initCipherUtil) {
		list.add(dynamicContainer("Encryption methods", Stream.of(
				getTest(cipherSuppl, "byte[] -> byte[]", (c) -> {
					initCipherUtil.accept(c);
					assertEquals(TestUtil.hashPlain(src),
							testDecrypt(cipherSuppl, new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(src))), initCipherUtil));
				}),	
				getTest(cipherSuppl, "File -> File", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), testDecrypt(cipherSuppl, new FileInputStream(fdest), initCipherUtil));
				}),
				getTest(cipherSuppl, "Base64 encoded String -> Base64 encoded String", (c) -> {
					initCipherUtil.accept(c);
					String result = c.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
					assertEquals(TestUtil.hashPlain(src), testDecrypt(cipherSuppl, new ByteArrayInputStream(Base64.getDecoder().decode(result)), initCipherUtil));
				}),
				getTest(cipherSuppl, "Hex encoded String -> Hex encoded String", (c) -> {
					initCipherUtil.accept(c);
					String result = c.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
					assertEquals(TestUtil.hashPlain(src), testDecrypt(cipherSuppl, new ByteArrayInputStream(HexFormat.of().parseHex(result)), initCipherUtil));
				}),
				getTest(cipherSuppl, "String -> byte[]", (c) -> {
					initCipherUtil.accept(c);
					assertEquals(TestUtil.hashPlain(randomStr.getBytes(TESTCHARSET)), testDecrypt(cipherSuppl, 
							new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET))), initCipherUtil));
				}),
				getTest(cipherSuppl, "Inputstream -> Outputstream", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), testDecrypt(cipherSuppl, new FileInputStream(fdest), initCipherUtil));
				}),
				getTest(cipherSuppl, "part of InputStream -> byte[]", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempPlainFile();
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
							testDecrypt(cipherSuppl, new ByteArrayInputStream(c.encryptToSingleBuffer(
									MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 16 * 1024))), initCipherUtil));
				}),
				getTest(cipherSuppl, "ReadableByteChannel -> WritableByteChannel", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempPlainFile();
					File fdest = mkEmptyTempFile();
					c.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)),
							testDecrypt(cipherSuppl, new FileInputStream(fdest), initCipherUtil));
				}),
				getTest(cipherSuppl, "From part of ReadableByteChannel", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempPlainFile();
					assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
							testDecrypt(cipherSuppl, new ByteArrayInputStream(
									c.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 16 * 1024))), initCipherUtil));
				})
			)));
			CipherUtil cc = cipherSuppl.get();
			initCipherUtil.accept(cc);
			final byte[] encrypted = cc.encryptToSingleBuffer(MessageProvider.from(src));
			final String srcHash = TestUtil.hashPlain(src);
			list.add(dynamicContainer("Decryption methods", Stream.of(
				getTest(cipherSuppl, "byte[] -> byte[]", (c) -> {
					initCipherUtil.accept(c);
					assertEquals(srcHash, TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(encrypted))));
				}),
				getTest(cipherSuppl, "File -> File", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				}),
				getTest(cipherSuppl, "Base64 encoded String -> Base64 encoded String", (c) -> {
					initCipherUtil.accept(c);
					String result = c.decryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(encrypted)));
					assertEquals(srcHash, TestUtil.hashPlain(Base64.getDecoder().decode(result)));
				}),
				getTest(cipherSuppl, "Hex encoded String -> Hex encoded String", (c) -> {
					initCipherUtil.accept(c);
					String result = c.decryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(encrypted)));
					assertEquals(srcHash, TestUtil.hashPlain(HexFormat.of().parseHex(result)));
				}),
				getTest(cipherSuppl, "Inputstream -> Outputstream", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
							MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				}),
				getTest(cipherSuppl, "ReadableByteChannel -> WritableByteChannel", (c) -> {
					initCipherUtil.accept(c);
					File fsrc = mkTempEncryptedFile(encrypted);
					File fdest = mkEmptyTempFile();
					c.decrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
							MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
					assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
				})
			)));
	}
	
	private static String testDecrypt(Supplier<? extends CipherUtil> cipherSuppl, InputStream is, Consumer<CipherUtil> initCipherUtil) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-512");
			CipherUtil c = cipherSuppl.get();
			initCipherUtil.accept(c);
			return HexFormat.of().formatHex(digest
					.digest(c.decryptToSingleBuffer(MessageProvider.from(is))));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
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