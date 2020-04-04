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

package com.nimbusds.openid.connect.sdk.federation.config;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsVerifier;


/**
 * Federation entity configuration success response.
 *
 * <p>Example HTTP response (with line breaks for clarity):
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/jose; charset=UTF-8
 *
 * eyJraWQiOiI4OHR3SGhGSFNiSk4xQnJ4cEdBT1A1Tk5RY3JEMFNBcEhiU3pVWjJpMjgwIiwiYWxn
 * IjoiUlMyNTYifQ.eyJzdWIiOiJodHRwczpcL1wvb3AuYzJpZC5jb20iLCJqd2tzIjp7ImtleXMiO
 * lt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lkIjoiODh0d0hoRkhTYkpOM
 * UJyeHBHQU9QNU5OUWNyRDBTQXBIYlN6VVoyaTI4MCIsIm4iOiJqYl8zeFBJWGhDM2JJRnFuVG8xb
 * nFDRHlwSzd6djBxNUJvUTZmNC1adXlfRWs2UFc2ZFdwQ1hGQ1R3c016YVRZV0M2VGViQnE2aGQ5T
 * 1A5ZXVSckl3ZjBxNnBOQ3o2NG9uMGNBbXcxbmJVXzNKc21wNzRxRl9HMV9ySTVrdVZ3Z0l1VHJQT
 * k40MUV3RlFYMGtMa2UyYTNVaHAyRTBOcHdBa2ZJa1B6ZFozTlNZVVd0TTRWTXA4SzBjN1dwRlpHS
 * EtYcWpXcnRWX1JQajRsV0dvYWRnRFJxVEg2R0kyTF9ESVRNRHJldlk2YzU4VlhBT1VvOHBjbGk4W
 * VVnV0J2UURqcEtGRFY5aU1IejFOZ2o0bzdRbGg5NjhFSnZNdUNXUjBKRWZhbEtvb3lQbXZGeUYwd
 * 1NUd2FseVh6M0xsOEFxY3d4Qm1Qb3JlQzA0RnhMVGV6R2Q5U1EifV19LCJpc3MiOiJodHRwczpcL
 * 1wvYWJjLWZlZGVyYXRpb24uYzJpZC5jb20iLCJleHAiOjIwMDAsImlhdCI6MTAwMH0.JTLM1NREw
 * OBqwHJin4LPBnzmGbHyx61wSx-CqUNwsd9u8u_PelVwo44X_GjV-7W2iPUHTrtnBZm7TURdzyrd6
 * M0s5V5g0GhSrQLe4HtX_X2gZbSxAUosQKwVltnwIw0lUDOAw7jk3aQ4URXmu0enBSrNb499sAshB
 * YWFqkrunUAcjoAGepRwhLJwmRjC21pfd5WB1fJHRkHPngeGJIp8nXbSAqJ_d-ks1Y7y0ddy3NOUX
 * qoBrIIrXRkXzOv6xyaifginDRVu6gZl8_v4k0rjqhnosWq8yDZCHLSu2YjMkCQ2neGivDGTlnfFE
 * oKfanrdIKy9uDnkdbgxLkjz8XEavA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.2.
 * </ul>
 */
public class FederationEntityConfigurationSuccessResponse extends FederationEntityConfigurationResponse {
	
	
	/**
	 * The content type.
	 */
	private static final ContentType CONTENT_TYPE = new ContentType("application", "jose", StandardCharsets.UTF_8);
	
	
	/**
	 * The entity statement as a signed JWT.
	 */
	private final SignedJWT signedStatement;
	
	
	/**
	 * Creates a new federation entity configuration success response.
	 *
	 * @param signedStatement The signed federation entity statement. Must
	 *                        not be {@code null}.
	 */
	public FederationEntityConfigurationSuccessResponse(final SignedJWT signedStatement) {
		
		if (signedStatement == null) {
			throw new IllegalArgumentException("The federation entity statement must not be null");
		}
		
		if ( ! JWSObject.State.SIGNED.equals(signedStatement.getState())) {
			throw new IllegalArgumentException("The federation entity statement must be signed");
		}
		
		this.signedStatement = signedStatement;
	}
	
	
	/**
	 * Returns the raw signed statement. No signature validation or general
	 * validation of the statement is performed.
	 *
	 * @return The signed statement as a JWT.
	 */
	public SignedJWT getSignedStatement() {
		
		return signedStatement;
	}
	
	
	/**
	 * Validates the signature, issue and expiration times of the JOSE
	 * (JWT) object and extracts the contained federation entity statement.
	 *
	 * @param expectedAudience The expected audience, {@code null} if not
	 *                         specified.
	 *
	 * @return The federation entity claims set.
	 *
	 * @throws ParseException   If the statement doesn't include the
	 *                          minimum required claims.
	 * @throws BadJOSEException If the signature is invalid.
	 * @throws JOSEException    If an internal signature validation
	 *                          exception is encountered.
	 */
	public EntityStatementClaimsSet validateAndExtractStatement(final Audience expectedAudience)
		throws ParseException, BadJOSEException, JOSEException {
		
		// Parse and validate min claims first
		JWTClaimsSet jwtClaimsSet;
		try {
			jwtClaimsSet = signedStatement.getJWTClaimsSet();
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(jwtClaimsSet);
		stmt.validateRequiredClaimsPresence();
		
		// Validate self-issued signature
		final JWKSet jwkSet = stmt.getJWKSet();
		
		DefaultJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(new JWSKeySelector() {
			@Override
			public List<? extends Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) {
				
				List<JWK> jwkMatches = new JWKSelector(JWKMatcher.forJWSHeader(header)).select(jwkSet);
				return new LinkedList<>(KeyConverter.toJavaKeys(jwkMatches));
			}
		});
		
		// Double check claims with JWT framework
		jwtProcessor.setJWTClaimsSetVerifier(new EntityStatementClaimsVerifier(expectedAudience));
		
		jwtProcessor.process(signedStatement, null);
		
		return stmt;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(CONTENT_TYPE);
		httpResponse.setContent(signedStatement.serialize());
		return httpResponse;
	}
	
	
	private static void ensureSigningJWKisPresentInSet(final JWK jwk, final JWKSet jwkSet)
		throws JOSEException {
		
		if (jwkSet == null) {
			throw new JOSEException("Missing JWK set");
		}
		
		Base64URL thumbprint = jwk.computeThumbprint();
		
		for (JWK k: jwkSet.getKeys()) {
			if (thumbprint.equals(k.computeThumbprint())) {
				return; // found
			}
		}
		throw new JOSEException("Signing JWK not found in JWK set");
	}
	
	
	private static JWSAlgorithm resolveSigningAlgorithm(final JWK jwt)
		throws JOSEException {
		
		KeyType jwkType = jwt.getKeyType();
		
		if (KeyType.RSA.equals(jwkType)) {
			
			if (jwt.getAlgorithm() != null) {
				return new JWSAlgorithm(jwt.getAlgorithm().getName());
			} else {
				return JWSAlgorithm.RS256; // default alg
			}
		} else if (KeyType.EC.equals(jwkType)) {
			ECKey ecJWK = jwt.toECKey();
			if (jwt.getAlgorithm() != null) {
				return new JWSAlgorithm(ecJWK.getAlgorithm().getName());
			} else {
				if (Curve.P_256.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES256;
				} else if (Curve.P_384.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES384;
				} else if (Curve.P_521.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES512;
				} else {
					throw new JOSEException("Unsupported ECDSA curve: " + ecJWK.getCurve());
				}
			}
		} else if (KeyType.OKP.equals(jwkType)){
			OctetKeyPair okp = jwt.toOctetKeyPair();
			if (Curve.Ed25519.equals(okp.getCurve())) {
				return JWSAlgorithm.EdDSA;
			} else {
				throw new JOSEException("Unsupported EdDSA curve: " + okp.getCurve());
			}
		} else {
			throw new JOSEException("Unsupported JWK type: " + jwkType);
		}
	}
	
	
	private static JWSSigner createSigner(final JWSAlgorithm jwsAlgorithm, final JWK privateJWK)
		throws JOSEException {
		
		if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
			return new RSASSASigner(privateJWK.toRSAKey());
		}
		
		if (JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
			return new ECDSASigner(privateJWK.toECKey());
		}
		
		if (JWSAlgorithm.Family.ED.contains(jwsAlgorithm)) {
			return new Ed25519Signer(privateJWK.toOctetKeyPair());
		}
		
		throw new JOSEException("Unsupported JWS algorithm: " + jwsAlgorithm);
	}
	
	
	/**
	 * Creates a new federation entity configuration success response.
	 *
	 * @param entityStatementClaimsSet The federation entity statement
	 *                                 claims set. Must not be
	 *                                 {@code null}.
	 * @param privateJWK               The private JWK to sign the
	 *                                 statement. Must be present in the
	 *                                 JWK set included in the statement.
	 *                                 Must not be {@code null}.
	 * @return The federation entity configuration success response.
	 *
	 * @throws JOSEException  If signing failed.
	 * @throws ParseException If parsing of the statement failed.
	 */
	public static FederationEntityConfigurationSuccessResponse create(final EntityStatementClaimsSet entityStatementClaimsSet,
									  final JWK privateJWK)
		throws JOSEException, ParseException {
		
		if (! privateJWK.isPrivate()) {
			throw new JOSEException("The signing JWK must be private");
		}
		
		ensureSigningJWKisPresentInSet(privateJWK, entityStatementClaimsSet.getJWKSet());
		
		JWSAlgorithm alg = resolveSigningAlgorithm(privateJWK);
		JWSHeader header = new JWSHeader.Builder(alg).keyID(privateJWK.getKeyID()).build();
		SignedJWT signedJWT = new SignedJWT(header, entityStatementClaimsSet.toJWTClaimsSet());
		signedJWT.sign(createSigner(alg, privateJWK));
		
		return new FederationEntityConfigurationSuccessResponse(signedJWT);
	}
	
	
	/**
	 * Parses a federation entity configuration success response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The federation entity configuration success response.
	 *
	 * @throws ParseException If HTTP response couldn't be parsed to a
	 *                        federation entity configuration success
	 *                        response.
	 */
	public static FederationEntityConfigurationSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(200);
		httpResponse.ensureEntityContentType(CONTENT_TYPE);
		
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(httpResponse.getContent());
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		return new FederationEntityConfigurationSuccessResponse(signedJWT);
	}
}
