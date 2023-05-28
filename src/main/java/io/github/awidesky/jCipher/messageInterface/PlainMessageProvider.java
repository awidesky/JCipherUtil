/*
 * Copyright (c) 2023 Eugene Hong
 *
 * This software is distributed under license. Use of this software
 * implies agreement with all terms and conditions of the accompanying
 * software license.
 * Please refer to LICENSE
 * */

package io.github.awidesky.jCipher.messageInterface;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;

public interface PlainMessageProvider extends MessageProvider {
	public static MessageProvider from(String str) {
		return from(str, Charset.defaultCharset());
	}
	public static MessageProvider from(String str, Charset encoding) {
		return MessageProvider.from(new ByteArrayInputStream(str.getBytes(encoding)));
	}
}
