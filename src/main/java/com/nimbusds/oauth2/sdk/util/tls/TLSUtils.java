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


import java.security.*;
import javax.net.ssl.*;


/**
 * TLS / SSL utilities.
 */
public final class TLSUtils {
	
	
	/**
	 * Creates a new SSL socket factory with with a custom trust store for
	 * server or CA root X.509 certificates / certificate chains.
	 *
	 * <p>The SSL socket factory is created using TLS 1.3, the default JCA
	 * provider and the default secure random generator.
	 *
	 * @param trustStore The trust store to use. Must be initialised /
	 *                   loaded. If {@code null} the default trust store
	 *                   for resolving the server certificates will be
	 *                   used.
	 *
	 * @return The SSL socket factory.
	 *
	 * @throws NoSuchAlgorithmException  On a unsupported TLS algorithm.
	 * @throws KeyStoreException         On a trust store exception.
	 * @throws KeyManagementException    On a key management exception.
	 * @throws UnrecoverableKeyException On a key retrieval exception.
	 */
	public static SSLSocketFactory createSSLSocketFactory(final KeyStore trustStore)
		throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		
		return createSSLSocketFactory(trustStore, null, null, TLSVersion.TLS_1_3);
	}
	
	
	/**
	 * Creates a new SSL socket factory with with a custom trust store for
	 * server or CA root X.509 certificates / certificate chains.
	 *
	 * <p>The SSL socket factory is created using the default JCA provider
	 * and the default secure random generator.
	 *
	 * @param trustStore The trust store to use. Must be initialised /
	 *                   loaded. If {@code null} the default trust store
	 *                   for resolving the server certificates will be
	 *                   used.
	 * @param tlsVersion The TLS version to use. {@link TLSVersion#TLS_1_3}
	 *                   is recommended. Must not be {@code null}.
	 *
	 * @return The SSL socket factory.
	 *
	 * @throws NoSuchAlgorithmException  On a unsupported TLS algorithm.
	 * @throws KeyStoreException         On a trust store exception.
	 * @throws KeyManagementException    On a key management exception.
	 * @throws UnrecoverableKeyException On a key retrieval exception.
	 */
	public static SSLSocketFactory createSSLSocketFactory(final KeyStore trustStore, final TLSVersion tlsVersion)
		throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		
		return createSSLSocketFactory(trustStore, null, null, tlsVersion);
	}
	
	
	/**
	 * Creates a new SSL socket factory with with a custom trust store for
	 * server (or CA) certificates and / or custom key store for client
	 * keys and certificates.
	 *
	 * <p>If a trust store is specified it should contain the required
	 * server or CA root X.509 certificates / certificate chains.
	 *
	 * <p>If a key store is specified it should contain the required one
	 * more private client keys with matching X.509 certificates.
	 *
	 * <p>The SSL socket factory is created using the default JCA provider
	 * and the default secure random generator.
	 *
	 * @param trustStore The trust store to use. Must be initialised /
	 *                   loaded. If {@code null} the default trust store
	 *                   for resolving the server certificates will be
	 *                   used.
	 * @param keyStore   The key store to use. Must be initialised /
	 *                   loaded. If {@code null} no client certificates
	 *                   will be presented.
	 * @param keyPw      The password protecting the client key(s), empty
	 *                   array if none or not applicable.
	 * @param tlsVersion The TLS version to use. {@link TLSVersion#TLS_1_3}
	 *                   is recommended. Must not be {@code null}.
	 *
	 * @return The SSL socket factory.
	 *
	 * @throws NoSuchAlgorithmException  On a unsupported TLS algorithm.
	 * @throws KeyStoreException         On a trust store exception.
	 * @throws KeyManagementException    On a key management exception.
	 * @throws UnrecoverableKeyException On a key retrieval exception.
	 */
	public static SSLSocketFactory createSSLSocketFactory(final KeyStore trustStore,
							      final KeyStore keyStore,
							      final char[] keyPw,
							      final TLSVersion tlsVersion)
		throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		
		final SSLContext sslContext = SSLContext.getInstance(tlsVersion.toString());
		
		TrustManager[] trustManagers = null;
		if (trustStore != null) {
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
			tmf.init(trustStore);
			trustManagers = tmf.getTrustManagers();
		}
		
		KeyManager[] keyManagers = null;
		if (keyStore != null) {
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
			kmf.init(keyStore, keyPw);
			keyManagers = kmf.getKeyManagers();
		}
		
		sslContext.init(keyManagers, trustManagers, null);
		
		return sslContext.getSocketFactory();
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private TLSUtils() {}
}
