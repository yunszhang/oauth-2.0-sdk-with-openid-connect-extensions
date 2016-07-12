package com.nimbusds.oauth2.sdk.auth.verifier;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
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

			assert authMethod.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

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

		ClientAuthenticationVerifier verifier = new ClientAuthenticationVerifier(selector, audienceSet);

		assertEquals(selector, verifier.getClientCredentialsSelector());
		assertEquals(audienceSet, verifier.getExpectedAudience());
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createVerifier() {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, EXPECTED_JWT_AUDIENCE);
	}


	public void testHappyClientSecretBasic()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyClientSecretPost()
		throws Exception{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyClientSecretJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		createVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyPrivateKeyJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		createVerifier().verify(clientAuthentication, null, null);
	}


	public void testInvalidClientSecretPost_badID()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("invalid-id"), VALID_CLIENT_SECRET);

		try {
			createVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_ID, e);
		}
	}


	public void testInvalidClientSecretPost_badSecret()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, new Secret("invalid-secret"));

		try {
			createVerifier().verify(clientAuthentication, null, null);
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
			createVerifier().verify(clientAuthentication, null, null);
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
			createVerifier().verify(clientAuthentication, null, null);
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
			createVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_CLAIMS, e);
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
			createVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_CLAIMS, e);
		}
	}


	public void testExpiredClientSecretJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000l);

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
			createVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_CLAIMS, e);
		}
	}


	public void testExpiredPrivateKeyJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000l);

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
			createVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_CLAIMS, e);
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

		createVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
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
			createVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_SIGNATURE, e);
		}
	}
}
