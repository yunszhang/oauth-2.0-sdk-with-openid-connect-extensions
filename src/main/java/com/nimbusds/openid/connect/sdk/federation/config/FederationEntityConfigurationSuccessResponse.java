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

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


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
	 * The entity statement.
	 */
	private final EntityStatement entityStatement;
	
	
	/**
	 * Creates a new federation entity configuration success response.
	 *
	 * @param entityStatement The entity statement. Must not be
	 *                        {@code null}.
	 */
	public FederationEntityConfigurationSuccessResponse(final EntityStatement entityStatement) {
		
		if (entityStatement == null) {
			throw new IllegalArgumentException("The federation entity statement must not be null");
		}
		this.entityStatement = entityStatement;
	}
	
	
	/**
	 * Returns the entity statement. No signature or expiration validation
	 * is performed.
	 *
	 * @return The entity statement.
	 */
	public EntityStatement getEntityStatement() {
		
		return entityStatement;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(CONTENT_TYPE);
		httpResponse.setContent(entityStatement.getSignedStatement().serialize());
		return httpResponse;
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
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		httpResponse.ensureEntityContentType(CONTENT_TYPE);
		
		String content = httpResponse.getContent();
		
		if (StringUtils.isBlank(content)) {
			throw new ParseException("Empty HTTP entity body");
		}
		
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(httpResponse.getContent());
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		return new FederationEntityConfigurationSuccessResponse(EntityStatement.parse(signedJWT));
	}
}
