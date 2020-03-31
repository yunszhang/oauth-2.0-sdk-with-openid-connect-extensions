/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Fetch entity statement success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.1.2.
 * </ul>
 */
@Immutable
public class FetchEntityStatementSuccessResponse extends FetchEntityStatementResponse {
	
	
	/**
	 * The entity statement as signed JWT.
	 */
	private final SignedJWT signedStmt;
	
	
	/**
	 * Creates a new fetch entity statement success response.
	 *
	 * @param signedStmt The signed entity statement as signed JWT. Must
	 *                   not be {@code null}.
	 */
	public FetchEntityStatementSuccessResponse(final SignedJWT signedStmt) {
		if (signedStmt == null) {
			throw new IllegalArgumentException("The signed entity statement must not be null");
		}
		if (! JWSObject.State.SIGNED.equals(signedStmt.getState())) {
			throw new IllegalArgumentException("The entity statement must be in signed state");
		}
		this.signedStmt = signedStmt;
	}
	
	
	/**
	 * Returns the signed entity statement. After the signature if
	 * validated the statement can be processed with
	 * {@link com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet}.
	 *
	 * @return The signed entity statement as signed JWT.
	 */
	public SignedJWT getSignedEntityStatement() {
		return signedStmt;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JOSE);
		httpResponse.setContent(getSignedEntityStatement().serialize());
		return httpResponse;
	}
	
	
	/**
	 * Parses a fetch entity statement success response from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The fetch entity statement success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FetchEntityStatementSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JOSE);
		
		try {
			return new FetchEntityStatementSuccessResponse(SignedJWT.parse(httpResponse.getContent()));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid signed entity statement: " + e.getMessage(), e);
		}
	}
}
