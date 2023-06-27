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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import io.github.awidesky.jCipher.cipher.symmetric.aes.AESKeySize;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_CBCCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_CTRCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_ECBCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.aes.AES_GCMCipherUtil;
import io.github.awidesky.jCipher.cipher.symmetric.chacha20.ChaCha20KeySize;
import io.github.awidesky.jCipher.cipher.symmetric.chacha20.ChaCha20_Poly1305CipherUtil;
import io.github.awidesky.jCipher.messageInterface.MessageConsumer;
import io.github.awidesky.jCipher.messageInterface.MessageProvider;
import io.github.awidesky.jCipher.metadata.key.KeyMetadata;

@DisplayName("ALL Cipher Tests")
class Test {

	static final int CIPHERUTILBUFFERSIZE = 501; //odd number for test
	static final Map<String, Stream<Supplier<CipherUtil>>> ciphers = Map.ofEntries(
			Map.entry("AES", Stream.of(
					() -> new AES_GCMCipherUtil(KeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_ECBCipherUtil(KeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_CTRCipherUtil(KeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new AES_CBCCipherUtil(KeyMetadata.DEFAULT.with(AESKeySize.SIZE_256), CIPHERUTILBUFFERSIZE)
				)),
			Map.entry("ChaCha20", Stream.of(
					() -> new ChaCha20_Poly1305CipherUtil(KeyMetadata.DEFAULT.with(ChaCha20KeySize.SIZE_256), CIPHERUTILBUFFERSIZE),
					() -> new ChaCha20_Poly1305CipherUtil(KeyMetadata.DEFAULT.with(ChaCha20KeySize.SIZE_256), CIPHERUTILBUFFERSIZE)
				))
			);
			

	static final Charset TESTCHARSET = Charset.forName("UTF-16"); 
	static final SecureRandom ran = new SecureRandom();
	
	static final byte[] src = new byte[7 * 1001]; //odd number for test
	static final String randomStr = "random String 1234!@#$";;
	
	static {
		ran.nextBytes(src);
	}
	
	@TestFactory
	@Execution(ExecutionMode.CONCURRENT)
	@DisplayName("test All")
	Collection<DynamicNode> testAll() throws NoSuchAlgorithmException, DigestException, IOException {
		
		List<DynamicNode> allTests = new ArrayList<>();

		ciphers.entrySet().stream().forEach(entry -> { //per AES, ChaCha20...
			allTests.add(dynamicContainer(entry.getKey(), entry.getValue().map(cipherSuppl -> { // per  AES_GCMCipherUtil, AES_ECBCipherUtil, ...
				Function<InputStream, String> testDecrypt = (is) -> {
					try {
						MessageDigest digest = MessageDigest.getInstance("SHA-512");
						return HexFormat.of().formatHex(digest
								.digest(cipherSuppl.get().init(TestUtil.password).decryptToSingleBuffer(MessageProvider.from(is))));
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
						return null;
					}
				};

				List<DynamicNode> singleCipherAlgorithmTests = new ArrayList<>(2);

				singleCipherAlgorithmTests.add(getTest(cipherSuppl, "byte[] key test", (c) -> {
					byte[] key = new byte[1024];
					new Random().nextBytes(key);
					c.init(key);
					assertEquals(TestUtil.hashPlain(src),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(MessageProvider.from(src))))));
				}));	
				singleCipherAlgorithmTests.add(getTest(cipherSuppl, "password test", (c) -> {
					c.init(TestUtil.password);
					assertEquals(TestUtil.hashPlain(src),
							TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(c.encryptToSingleBuffer(MessageProvider.from(src))))));
				}));	
				
				singleCipherAlgorithmTests.add(dynamicContainer("Encryption methods", Stream.of(
					getTest(cipherSuppl, "byte[] -> byte[]", (c) -> {
						c.init(TestUtil.password);
						assertEquals(TestUtil.hashPlain(src),
								testDecrypt.apply(new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(src)))));
					}),	
					getTest(cipherSuppl, "File -> File", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), testDecrypt.apply(new FileInputStream(fdest)));
					}),
					getTest(cipherSuppl, "Base64 encoded String -> Base64 encoded String", (c) -> {
						c.init(TestUtil.password);
						String result = c.encryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(src)));
						assertEquals(TestUtil.hashPlain(src), testDecrypt.apply(new ByteArrayInputStream(Base64.getDecoder().decode(result))));
					}),
					getTest(cipherSuppl, "Hex encoded String -> Hex encoded String", (c) -> {
						c.init(TestUtil.password);
						String result = c.encryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(src)));
						assertEquals(TestUtil.hashPlain(src), testDecrypt.apply(new ByteArrayInputStream(HexFormat.of().parseHex(result))));
					}),
					getTest(cipherSuppl, "String -> byte[]", (c) -> {
						c.init(TestUtil.password);
						assertEquals(TestUtil.hashPlain(randomStr.getBytes(TESTCHARSET)), testDecrypt.apply(
								new ByteArrayInputStream(c.encryptToSingleBuffer(MessageProvider.from(randomStr, TESTCHARSET)))));
					}),
					getTest(cipherSuppl, "Inputstream -> Outputstream", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
								MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)), testDecrypt.apply(new FileInputStream(fdest)));
					}),
					getTest(cipherSuppl, "part of InputStream -> byte[]", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
								testDecrypt.apply(new ByteArrayInputStream(c.encryptToSingleBuffer(
										MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc)), 16 * 1024)))));
					}),
					getTest(cipherSuppl, "ReadableByteChannel -> WritableByteChannel", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						File fdest = mkEmptyTempFile();
						c.encrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
								MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc)),
								testDecrypt.apply(new FileInputStream(fdest)));
					}),
					getTest(cipherSuppl, "From part of ReadableByteChannel", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempPlainFile();
						assertEquals(TestUtil.hashPlain(new FileInputStream(fsrc), 16 * 1024),
								testDecrypt.apply(new ByteArrayInputStream(
										c.encryptToSingleBuffer(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ), 16 * 1024)))));
					})
				)));
				CipherUtil cc = cipherSuppl.get();
				cc.init(TestUtil.password);
				final byte[] encrypted = cc.encryptToSingleBuffer(MessageProvider.from(src));
				final String srcHash = TestUtil.hashPlain(src);
				singleCipherAlgorithmTests.add(dynamicContainer("Decryption methods", Stream.of(
					getTest(cipherSuppl, "byte[] -> byte[]", (c) -> {
						c.init(TestUtil.password);
						assertEquals(srcHash, TestUtil.hashPlain(c.decryptToSingleBuffer(MessageProvider.from(encrypted))));
					}),
					getTest(cipherSuppl, "File -> File", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile(encrypted);
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(fsrc), MessageConsumer.to(fdest));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					}),
					getTest(cipherSuppl, "Base64 encoded String -> Base64 encoded String", (c) -> {
						c.init(TestUtil.password);
						String result = c.decryptToBase64(MessageProvider.fromBase64(Base64.getEncoder().encodeToString(encrypted)));
						assertEquals(srcHash, TestUtil.hashPlain(Base64.getDecoder().decode(result)));
					}),
					getTest(cipherSuppl, "Hex encoded String -> Hex encoded String", (c) -> {
						c.init(TestUtil.password);
						String result = c.decryptToHexString(MessageProvider.fromHexString(HexFormat.of().formatHex(encrypted)));
						assertEquals(srcHash, TestUtil.hashPlain(HexFormat.of().parseHex(result)));
					}),
					getTest(cipherSuppl, "Inputstream -> Outputstream", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile(encrypted);
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(new BufferedInputStream(new FileInputStream(fsrc))),
								MessageConsumer.to(new BufferedOutputStream(new FileOutputStream(fdest))));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					}),
					getTest(cipherSuppl, "ReadableByteChannel -> WritableByteChannel", (c) -> {
						c.init(TestUtil.password);
						File fsrc = mkTempEncryptedFile(encrypted);
						File fdest = mkEmptyTempFile();
						c.decrypt(MessageProvider.from(FileChannel.open(fsrc.toPath(), StandardOpenOption.READ)),
								MessageConsumer.to(FileChannel.open(fdest.toPath(), StandardOpenOption.WRITE)));
						assertEquals(srcHash, TestUtil.hashPlain(new FileInputStream(fdest)));
					})
				)));
				return dynamicContainer(cipherSuppl.get().toString(), singleCipherAlgorithmTests);
			})));
		});
		
		
		return allTests;
	}
	
	private static DynamicTest getTest(Supplier<CipherUtil> cipherSuppl, String name, ThrowableConsumer<CipherUtil> testCode) {
		return dynamicTest(name, () -> testCode.accept(cipherSuppl.get()));
	}
	
	private static File mkTempPlainFile() throws IOException {
		return mkTempFile(src);
	}
	
	private static File mkTempEncryptedFile(byte[] input) throws IOException {
		return mkTempFile(input);
	}
	
	private static File mkTempFile(byte[] data) throws IOException {
		File f = Files.createTempFile("AESGCMTestSrc", "bin").toFile();
		//File fsrc = new File(".\\test.bin");
		if(f.exists()) { f.delete(); f.createNewFile(); }
		f.deleteOnExit();
		BufferedOutputStream bo = new BufferedOutputStream(new FileOutputStream(f));
		bo.write(data);
		bo.close();
		return f;
	}
	private static File mkEmptyTempFile() throws IOException {
		File f = Files.createTempFile("AESGCMTestEmpty", "bin").toFile();
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