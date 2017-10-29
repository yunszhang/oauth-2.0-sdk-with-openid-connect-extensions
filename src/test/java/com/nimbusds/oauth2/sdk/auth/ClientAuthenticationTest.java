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

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;


/**
 * Tests the base client authentication class.
 */
public class ClientAuthenticationTest extends TestCase {


	// See issue 141
	public void testParseClientSecretPostNullSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=407408718192.apps.googleusercontent.com&client_secret=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}


	public void testParseClientSecretJWTNull()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_assertion_type=&client_assertion=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}
	
	
	public void testPublicKeyTLSClientCertificateAuthentication()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		
		SelfSignedTLSClientAuthentication clientAuth = (SelfSignedTLSClientAuthentication) ClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals(clientCert, clientAuth.getClientX509Certificate());
	}
	
	
	public void testTLSClientCertificateAuthentication()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=123");
		httpRequest.setClientX509CertificateSubjectDN("cn=client-123");
		httpRequest.setClientX509CertificateRootDN("cn=root-CA");
		
		TLSClientAuthentication clientAuth = (TLSClientAuthentication) ClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals("cn=client-123", clientAuth.getClientX509CertificateSubjectDN());
		assertEquals("cn=root-CA", clientAuth.getClientX509CertificateRootDN());
	}
	
	
	public void testClientAuthenticationNone()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("client_id=123");
		
		assertNull(ClientAuthentication.parse(httpRequest));
	}
}
