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

package com.nimbusds.oauth2.sdk.auth;


import java.net.URL;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;


public class PublicKeyTLSClientAuthenticationTest extends TestCase {
	
	
	public void testSSLSocketFactoryConstructor_defaultSSL()
		throws Exception {
		
		PublicKeyTLSClientAuthentication clientAuth = new PublicKeyTLSClientAuthentication(
			new ClientID("123"),
			(SSLSocketFactory)null);
		
		assertEquals(ClientAuthenticationMethod.PUB_KEY_TLS_CLIENT_AUTH, clientAuth.getMethod());
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertNull(clientAuth.getClientX509Certificate());
		
		HTTPRequest httpRequest = new HTTPRequest(
			HTTPRequest.Method.POST,
			new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		assertNull(httpRequest.getSSLSocketFactory());
		
		clientAuth.applyTo(httpRequest);
		
		assertNull(httpRequest.getSSLSocketFactory());
	}
	
	
	public void testSSLSocketFactoryConstructor()
		throws Exception {
		
		SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		
		PublicKeyTLSClientAuthentication clientAuth = new PublicKeyTLSClientAuthentication(
			new ClientID("123"),
			sslSocketFactory
		);
		
		assertEquals(ClientAuthenticationMethod.PUB_KEY_TLS_CLIENT_AUTH, clientAuth.getMethod());
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertEquals(sslSocketFactory, clientAuth.getSSLSocketFactory());
		assertNull(clientAuth.getClientX509Certificate());
		
		HTTPRequest httpRequest = new HTTPRequest(
			HTTPRequest.Method.POST,
			new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		assertNull(httpRequest.getSSLSocketFactory());
		
		clientAuth.applyTo(httpRequest);
		
		assertEquals(sslSocketFactory, httpRequest.getSSLSocketFactory());
	}
	
	
	public void testCertificateConstructor()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		PublicKeyTLSClientAuthentication clientAuth = new PublicKeyTLSClientAuthentication(
			new ClientID("123"),
			clientCert);
		
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals(clientCert, clientAuth.getClientX509Certificate());
		
		// This constructor is not intended to be used for setting an
		// HTTPRequest, but still this shouldn't produce any errors
		HTTPRequest httpRequest = new HTTPRequest(
			HTTPRequest.Method.POST,
			new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		assertNull(httpRequest.getSSLSocketFactory());
		
		clientAuth.applyTo(httpRequest);
		
		assertNull(httpRequest.getSSLSocketFactory());
	}
	
	
	public void testParse_missingPostEntityBody()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		try {
			PublicKeyTLSClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP POST request entity body", e.getMessage());
		}
	}
	
	
	public void testParse_missingClientID()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("a=b");
		
		try {
			PublicKeyTLSClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
		}
	}
	
	
	public void testParse_emptyClientID()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=");
		
		try {
			PublicKeyTLSClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
		}
	}
	
	
	public void testParse_missingClientCertificate()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=123");
		
		try {
			PublicKeyTLSClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client X.509 certificate", e.getMessage());
		}
	}
	
	
	public void testParse_ok()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		
		PublicKeyTLSClientAuthentication clientAuth = PublicKeyTLSClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals(clientCert, clientAuth.getClientX509Certificate());
	}
}
