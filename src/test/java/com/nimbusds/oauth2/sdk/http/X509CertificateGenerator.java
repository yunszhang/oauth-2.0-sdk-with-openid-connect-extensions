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

package com.nimbusds.oauth2.sdk.http;


import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.bouncycastle.operator.OperatorCreationException;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;


public class X509CertificateGenerator {
	
	
	public static X509Certificate generateCertificate(final Issuer issuer,
							  final Subject subject,
							  final RSAPublicKey rsaPublicKey,
							  final RSAPrivateKey rsaPrivateKey)
		throws IOException, OperatorCreationException {
		
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L); // 1 second ago
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		
		return X509CertificateUtils.generate(issuer, subject, nbf, exp, rsaPublicKey, rsaPrivateKey);
	}
	

	/**
	 * Technically this is not allowed (a self signed certificate should always be
	 * self issued), but for tests this is good enough to simulate a PKI certificate.
	 */
	public static X509Certificate generateSelfSignedNotSelfIssuedCertificate(final String issuer,
			final String subject)
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

		return generateCertificate(new Issuer(issuer), new Subject(subject), rsaPublicKey, rsaPrivateKey);
	}
	
	public static X509Certificate generateSelfSignedCertificate(final Issuer issuer,
								    final RSAPublicKey rsaPublicKey,
								    final RSAPrivateKey rsaPrivateKey)
		throws IOException, OperatorCreationException {
		
		return generateCertificate(issuer, new Subject(issuer.getValue()), rsaPublicKey, rsaPrivateKey);
	}
	
	
	public static X509Certificate generateSampleClientCertificate()
		throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		return X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			rsaPublicKey,
			rsaPrivateKey);
	}
}
