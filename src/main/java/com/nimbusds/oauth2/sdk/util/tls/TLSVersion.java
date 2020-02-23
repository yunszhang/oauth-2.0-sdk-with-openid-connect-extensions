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

package com.nimbusds.oauth2.sdk.util.tls;


/**
 * TLS version.
 *
 * <p>See https://docs.oracle.com/javase/10/docs/specs/security/standard-names.html#sslcontext-algorithms
 */
public enum TLSVersion {
	
	
	/**
	 * Unspecified TLS.
	 */
	TLS("TLS"),
	
	
	/**
	 * The TLS Protocol Version 1.0 (RFC 2246).
	 */
	TLS_1("TLSv1"),
	
	
	/**
	 * The Transport Layer Security (TLS) Protocol Version 1.1 (RFC 4346).
	 */
	TLS_1_1("TLSv1.1"),
	
	
	/**
	 * The Transport Layer Security (TLS) Protocol Version 1.2 (RFC 5246).
	 */
	TLS_1_2("TLSv1.2"),
	
	
	/**
	 * Recommended: The Transport Layer Security (TLS) Protocol Version 1.3
	 * (RFC 8446).
	 */
	TLS_1_3("TLSv1.3");
	
	
	/**
	 * The algorithm value.
	 */
	private String value;
	
	
	TLSVersion(final String value) {
		this.value = value;
	}
	
	
	@Override
	public String toString() {
		return value;
	}
}
