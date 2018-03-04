/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk.util;


/**
 * String utilities. Replicates Apache Commons Lang 3.
 */
public final class StringUtils {
	
	
	/**
	 * Returns {@code true} if the specified char sequence is all blank,
	 * empty or {@code null}.
	 *
	 * @param cs The char sequence. May be {@code null}.
	 *
	 * @return {@code true} if the specified char sequence is all blank,
	 *         empty or {@code null}, else {@code false}.
	 */
	public static boolean isBlank(CharSequence cs) {
		
		int strLen;
		if (cs != null && (strLen = cs.length()) != 0) {
			for(int i = 0; i < strLen; ++i) {
				if (!Character.isWhitespace(cs.charAt(i))) {
					return false;
				}
			}
			
			return true;
		} else {
			return true;
		}
	}
	
	
	/**
	 * Returns {@code true} if the specified char sequence is not all
	 * blank, not empty and not {@code null}.
	 *
	 * @param cs The char sequence. May be {@code null}.
	 *
	 * @return {@code true} if the specified char sequence is not all
	 *         blank, not empty and not {@code null}, else {@code false}.
	 */
	public static boolean isNotBlank(CharSequence cs) {
		
		return !isBlank(cs);
	}
}
