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

package com.nimbusds.oauth2.sdk.auth.verifier;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import junit.framework.TestCase;


/**
 * Tests the client authentication verifier.
 */
public class ClientAuthenticationVerifierTest extends TestCase {


	private static final ClientID VALID_CLIENT_ID = new ClientID("123");


	private static final Secret VALID_CLIENT_SECRET = new Secret();


	private static final Set<Audience> EXPECTED_JWT_AUDIENCE = new LinkedHashSet<>(Arrays.asList(
		new Audience("https://c2id.com/token"),
		new Audience("https://c2id.com")));
	
	
	private static final String VALID_SUBJECT_DN = "cn=client-123";
	
	
	private static final String VALID_ROOT_DN = "cn=root-CA";

	
	private static final RSAKey VALID_RSA_KEY_PAIR_1;


	private static final RSAKey VALID_RSA_KEY_PAIR_2;


	private static final RSAKey INVALID_RSA_KEY_PAIR;


	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

			KeyPair keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.build();

			keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("2")
				.build();

			keyPair = gen.generateKeyPair();
			INVALID_RSA_KEY_PAIR = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.build();

		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	private static final ClientCredentialsSelector<ClientMetadata> CLIENT_CREDENTIALS_SELECTOR = new ClientCredentialsSelector<ClientMetadata>() {


		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<ClientMetadata> context)
			throws InvalidClientException {

			assert authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			return Collections.singletonList(VALID_CLIENT_SECRET);
		}


		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID,
								  ClientAuthenticationMethod authMethod,
								  JWSHeader jwsHeader,
								  boolean forceRefresh,
								  Context<ClientMetadata> context)
			throws InvalidClientException {

			final Set<ClientAuthenticationMethod> permittedClientAuthMethods =
				new HashSet<>(Arrays.asList(
					ClientAuthenticationMethod.PRIVATE_KEY_JWT,
					ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
			
			assert permittedClientAuthMethods.contains(authMethod);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			try {
				if (!forceRefresh) {
					return Collections.singletonList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey());
				} else {
					// Simulate reload
					return Arrays.asList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), VALID_RSA_KEY_PAIR_2.toRSAPublicKey());
				}

			} catch (JOSEException e) {
				fail(e.getMessage());
				throw InvalidClientException.NO_MATCHING_JWK;
			}
		}
	};
	
	
	private static final ClientX509CertificateBindingVerifier<ClientMetadata> CERT_BINDING_VERIFIER = new ClientX509CertificateBindingVerifier<ClientMetadata>() {
		
		@Override
		public void verifyCertificateBinding(ClientID clientID,
						     String subjectDN,
						     String rootDN,
						     Context<ClientMetadata> ctx)
			throws InvalidClientException {
			
			if (! VALID_CLIENT_ID.equals(clientID)) {
				throw InvalidClientException.BAD_ID;
			}
			
			if (! VALID_SUBJECT_DN.equalsIgnoreCase(subjectDN)) {
				throw new InvalidClientException("Bad subject DN");
			}
			
			if (rootDN != null && ! VALID_ROOT_DN.equalsIgnoreCase(rootDN)) {
				throw new InvalidClientException("Bad root DN");
			}
		}
	};


	public void testGetters() {

		ClientCredentialsSelector selector = new ClientCredentialsSelector() {
			@Override
			public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) throws InvalidClientException {
				return null;
			}


			@Override
			public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context context) throws InvalidClientException {
				return null;
			}
		};

		Set<Audience> audienceSet = new HashSet<>();
		audienceSet.add(new Audience("https://c2id.com/token"));

		ClientAuthenticationVerifier verifier = new ClientAuthenticationVerifier(selector, null, audienceSet);

		assertEquals(selector, verifier.getClientCredentialsSelector());
		assertNull(verifier.getClientX509CertificateBindingVerifier());
		assertEquals(audienceSet, verifier.getExpectedAudience());
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createBasicVerifier() {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, null, EXPECTED_JWT_AUDIENCE);
	}
	
	
	private static ClientAuthenticationVerifier<ClientMetadata> createVerifierWithPKIBoundCertSupport() {
		
		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, CERT_BINDING_VERIFIER, EXPECTED_JWT_AUDIENCE);
	}


	public void testHappyClientSecretBasic()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyClientSecretPost()
		throws Exception{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyClientSecretJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyPrivateKeyJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testInvalidClientSecretPost_badID()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("invalid-id"), VALID_CLIENT_SECRET);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_ID, e);
		}
	}


	public void testInvalidClientSecretPost_badSecret()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, new Secret("invalid-secret"));

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_SECRET, e);
		}
	}


	public void testInvalidClientSecretJWT_badHMAC()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_HMAC, e);
		}
	}


	public void testInvalidPrivateKeyJWT_badSignature()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_SIGNATURE, e);
		}
	}


	public void testClientSecretJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://other.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]", e.getMessage());
		}
	}


	public void testPrivateKeyJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://other.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]", e.getMessage());
		}
	}


	public void testExpiredClientSecretJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new MACSigner(VALID_CLIENT_SECRET.getValueBytes()));

		ClientAuthentication clientAuthentication = new ClientSecretJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Expired JWT", e.getMessage());
		}
	}


	public void testExpiredPrivateKeyJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(VALID_RSA_KEY_PAIR_1));

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Expired JWT", e.getMessage());
		}
	}


	public void testReloadRemoteJWKSet()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}


	public void testReloadRemoteJWKSet_badSignature()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_SIGNATURE, e);
		}
	}
	
	
	public void testPubKeyTLSClientAuth_ok()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}
	
	
	public void testPubKeyTLSClientAuth_okWithReload()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_2.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}
	
	public void testPubKeyTLSClientAuth_badSignature()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			INVALID_RSA_KEY_PAIR.toRSAPublicKey(),
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Couldn't validate client X.509 certificate signature: No matching registered client JWK found", e.getMessage());
		}
	}
	
	public void testPubKeyTLSClientAuth_missingCertificate()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			(SSLSocketFactory) null);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Missing client X.509 certificate", e.getMessage());
		}
	}
	
	
	public void testTLSClientAuth_ok()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new TLSClientAuthentication(
			VALID_CLIENT_ID,
			VALID_SUBJECT_DN,
			VALID_ROOT_DN
		);
		
		createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
	}
	
	
	public void testTLSClientAuth_ok_rootDNMissing()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new TLSClientAuthentication(
			VALID_CLIENT_ID,
			VALID_SUBJECT_DN,
			null
		);
		
		createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
	}
	
	
	public void testTLSClientAuth_badSubjectDN()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new TLSClientAuthentication(
			VALID_CLIENT_ID,
			"cn=invalid-subject",
			VALID_ROOT_DN
		);
		
		try {
			createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Bad subject DN", e.getMessage());
		}
	}
	
	
	public void testTLSClientAuth_badRootDN()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new TLSClientAuthentication(
			VALID_CLIENT_ID,
			VALID_SUBJECT_DN,
			"cn=invalid-root-ca"
		);
		
		try {
			createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Bad root DN", e.getMessage());
		}
	}
}
