/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky;

public interface CipherGenerator {

	public CipherGenerator getEncrypter(char[] key);
	public CipherGenerator getDecrypter(char[] key);
	public CipherGenerator getEncrypter(byte[] key);
	public CipherGenerator getDecrypter(byte[] key);
	public CipherGenerator getRandomKeyEncrypter();
	public CipherGenerator getRandomKeyDecrypter();
	
}
