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
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class X509CertificateGenerator {
	
	
	public static X509Certificate generateSelfSignedCertificate(final Issuer issuer,
								    final RSAPublicKey rsaPublicKey,
								    final RSAPrivateKey rsaPrivateKey)
		throws NoSuchAlgorithmException, IOException, OperatorCreationException, KeyStoreException {
		
		X500Name certIssuer = new X500Name("cn=" + issuer);
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=" + issuer);
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			certIssuer,
			serialNumber,
			nbf,
			exp,
			subject,
			rsaPublicKey
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(rsaPrivateKey));
		return X509CertUtils.parse(certHolder.getEncoded());
	}
}
