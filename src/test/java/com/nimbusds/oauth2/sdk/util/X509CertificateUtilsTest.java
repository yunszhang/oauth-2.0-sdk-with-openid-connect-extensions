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


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


public class X509CertificateUtilsTest extends TestCase {
	
	
	public static final RSAPublicKey PUBLIC_KEY;
	
	
	public static final RSAPrivateKey PRIVATE_KEY;
	
	
	static {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			PUBLIC_KEY = (RSAPublicKey)keyPair.getPublic();
			PRIVATE_KEY = (RSAPrivateKey)keyPair.getPrivate();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testHasMatchingIssuerAndSubject_true()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("123"),
			PUBLIC_KEY,
			PRIVATE_KEY);
		
		assertTrue(X509CertificateUtils.hasMatchingIssuerAndSubject(cert));
	}
	
	
	public void testHasMatchingIssuerAndSubject_false()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY);
		
		assertFalse(X509CertificateUtils.hasMatchingIssuerAndSubject(cert));
	}
	
	
	public void testIsSelfIssued_positive()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		assertTrue(X509CertificateUtils.isSelfIssued(cert));
		assertTrue(X509CertificateUtils.isSelfSigned(cert));
	}
	
	
	public void testIsSelfIssued_negative()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		assertFalse(X509CertificateUtils.isSelfIssued(cert));
		assertTrue(X509CertificateUtils.isSelfSigned(cert));
	}
}
