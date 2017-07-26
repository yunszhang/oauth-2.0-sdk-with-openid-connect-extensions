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


import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * X.509 certificate utilities.
 */
public class X509CertificateUtils {
	
	
	/**
	 * Checks if the specified X.509 certificate is self-issued, i.e. it
	 * has a matching issuer and subject, and the public key can be used to
	 * successfully validate the certificate's digital signature.
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return {@code true} if the X.509 certificate is self-issued, else
	 *         {@code false}.
	 */
	public static boolean isSelfIssued(final X509Certificate cert) {
		
		Principal issuer = cert.getIssuerDN();
		Principal subject = cert.getSubjectDN();
		
		return issuer != null && subject != null && issuer.equals(subject) && isSelfSigned(cert);
	}
	
	
	/**
	 * Checks if the specified X.509 certificate is self-signed, i.e. the
	 * public key can be used to successfully validate the certificate's
	 * digital signature.
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return {@code true} if the X.509 certificate is self-signed, else
	 *         {@code false}.
	 */
	public static boolean isSelfSigned(final X509Certificate cert) {
		
		PublicKey publicKey = cert.getPublicKey();
		
		try {
			cert.verify(publicKey);
		} catch (CertificateException| NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
			return false;
		}
		
		return true;
	}
}
