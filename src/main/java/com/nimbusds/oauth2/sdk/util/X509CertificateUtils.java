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


import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;


/**
 * X.509 certificate utilities.
 */
public final class X509CertificateUtils {
	
	
	/**
	 * Checks if the issuer DN and the subject DN of the specified X.509
	 * certificate match. The matched DNs are not normalised.
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return {@code true} if the issuer DN and and subject DN match, else
	 *         {@code false}.
	 */
	public static boolean hasMatchingIssuerAndSubject(final X509Certificate cert) {
		
		Principal issuer = cert.getIssuerDN();
		Principal subject = cert.getSubjectDN();
		
		return issuer != null && issuer.equals(subject);
	}
	
	
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
		
		return hasMatchingIssuerAndSubject(cert) && isSelfSigned(cert);
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
		
		return hasValidSignature(cert, publicKey);
	}
	
	
	/**
	 * Validates the signature of a X.509 certificate with the specified
	 * public key.
	 *
	 * @param cert   The X.509 certificate. Must not be {@code null}.
	 * @param pubKey The public key to use for the validation. Must not be
	 *               {@code null}.
	 *
	 * @return {@code true} if the signature is valid, else {@code false}.
	 */
	public static boolean hasValidSignature(final X509Certificate cert,
						final PublicKey pubKey) {
		
		try {
			cert.verify(pubKey);
		} catch (Exception e) {
			return false;
		}
		
		return true;
	}
	
	
	/**
	 * Returns {@code true} if the public key of the X.509 certificate
	 * matches the specified public key.
	 *
	 * @param cert   The X.509 certificate. Must not be {@code null}.
	 * @param pubKey The public key to compare. Must not be {@code null}.
	 *
	 * @return {@code true} if the two public keys match, else
	 *         {@code false}.
	 */
	public static boolean publicKeyMatches(final X509Certificate cert,
					       final PublicKey pubKey) {
		
		PublicKey certPubKey = cert.getPublicKey();
		
		return Arrays.equals(certPubKey.getEncoded(), pubKey.getEncoded());
	}
	
	
	/**
	 * Generates a new X.509 certificate. The certificate is provisioned
	 * with a 64-bit random serial number.
	 *
	 * <p>Signing algorithm:
	 *
	 * <ul>
	 *     <li>For RSA signing keys: SHA256withRSA
	 *     <li>For EC signing keys: SHA256withECDSA
	 * </ul>
	 *
	 * @param issuer     The issuer. Will be prepended by {@code cn=} in
	 *                   the certificate to ensure a valid Distinguished
	 *                   Name (DN). Must not be {@code null}.
	 * @param subject    The subject. Will be prepended by {@code cn=} in
	 *                   the certificate to ensure a valid Distinguished
	 *                   Name (DN). Must not be {@code null}.
	 * @param nbf        Date before which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param exp        Date after which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param certKey    The public key to include in the certificate. Must
	 *                   not be {@code null}.
	 * @param signingKey The signing private key. Must not be {@code null}.
	 *
	 * @return The X.509 certificate.
	 *
	 * @throws OperatorCreationException On a generation exception.
	 * @throws IOException               On a byte buffer exception.
	 */
	public static X509Certificate generate(final X500Principal issuer,
					       final X500Principal subject,
					       final Date nbf,
					       final Date exp,
					       final PublicKey certKey,
					       final PrivateKey signingKey)
		throws OperatorCreationException, IOException {
		
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		
		final String signingAlg;
		if ("RSA".equalsIgnoreCase(signingKey.getAlgorithm())) {
			signingAlg = "SHA256withRSA";
		} else if ("EC".equalsIgnoreCase(signingKey.getAlgorithm())) {
			signingAlg = "SHA256withECDSA";
		} else {
			throw new OperatorCreationException("Unsupported signing key algorithm: " + signingKey.getAlgorithm());
		}
		
		X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			certKey)
			.build(new JcaContentSignerBuilder(signingAlg).build(signingKey));
		
		return X509CertUtils.parse(certHolder.getEncoded());
	}
	
	
	/**
	 * Generates a new X.509 certificate. The certificate is provisioned
	 * with a 64-bit random serial number.
	 *
	 * <p>Signing algorithm:
	 *
	 * <ul>
	 *     <li>For RSA signing keys: SHA256withRSA
	 *     <li>For EC signing keys: SHA256withECDSA
	 * </ul>
	 *
	 * @param issuer     The issuer. Will be prepended by {@code cn=} in
	 *                   the certificate to ensure a valid Distinguished
	 *                   Name (DN). Must not be {@code null}.
	 * @param subject    The subject. Will be prepended by {@code cn=} in
	 *                   the certificate to ensure a valid Distinguished
	 *                   Name (DN). Must not be {@code null}.
	 * @param nbf        Date before which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param exp        Date after which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param certKey    The public key to include in the certificate. Must
	 *                   not be {@code null}.
	 * @param signingKey The signing private key. Must not be {@code null}.
	 *
	 * @return The X.509 certificate.
	 *
	 * @throws OperatorCreationException On a generation exception.
	 * @throws IOException               On a byte buffer exception.
	 */
	public static X509Certificate generate(final Issuer issuer,
					       final Subject subject,
					       final Date nbf,
					       final Date exp,
					       final PublicKey certKey,
					       final PrivateKey signingKey)
		throws OperatorCreationException, IOException {
		
		return generate(new X500Principal("cn=" + issuer), new X500Principal("cn=" + subject), nbf, exp, certKey, signingKey);
	}
	
	
	/**
	 * Generates a new self-signed and self-issued X.509 certificate. The
	 * certificate is provisioned with a 64-bit random serial number.
	 *
	 * <p>Signing algorithm:
	 *
	 * <ul>
	 *     <li>For RSA signing keys: SHA256withRSA
	 *     <li>For EC signing keys: SHA256withECDSA
	 * </ul>
	 *
	 * @param issuer     The issuer, also used to set the subject. Will be
	 *                   prepended by {@code cn=} in the certificate to
	 *                   ensure a valid Distinguished Name (DN). Must not
	 *                   be {@code null}.
	 * @param nbf        Date before which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param exp        Date after which the certificate is not valid.
	 *                   Must not be {@code null}.
	 * @param certKey    The public key to include in the certificate. Must
	 *                   not be {@code null}.
	 * @param signingKey The signing private key. Must not be {@code null}.
	 *
	 * @return The X.509 certificate.
	 *
	 * @throws OperatorCreationException On a generation exception.
	 * @throws IOException               On a byte buffer exception.
	 */
	public static X509Certificate generateSelfSigned(final Issuer issuer,
							 final Date nbf,
							 final Date exp,
							 final PublicKey certKey,
							 final PrivateKey signingKey)
		throws OperatorCreationException, IOException {
		
		return generate(issuer, new Subject(issuer.getValue()), nbf, exp, certKey, signingKey);
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private X509CertificateUtils() {}
}
