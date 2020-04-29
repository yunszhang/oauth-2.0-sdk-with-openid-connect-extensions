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


import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Entity listing request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.3.1.
 * </ul>
 */
@Immutable
public class EntityListingRequest extends FederationAPIRequest {
	
	
	/**
	 * The issuer.
	 */
	private final Issuer issuer;
	
	
	private final EntityListingSpec listingSpec;
	
	
	/**
	 * Creates a new entity listing request.
	 *
	 * @param endpoint    The federation API endpoint. Must not be
	 *                    {@code null}.
	 * @param issuer      The issuer entity identifier. Must not be
	 *                    {@code null}.
	 * @param listingSpec The entity listing spec. Must not be
	 *                    {@code null}.
	 */
	public EntityListingRequest(final URI endpoint, final Issuer issuer, final EntityListingSpec listingSpec) {
		super(endpoint, OperationType.LISTING);
		if (issuer == null) {
			throw new IllegalArgumentException("The issuer must not be null");
		}
		this.issuer = issuer;
		if (listingSpec == null) {
			throw new IllegalArgumentException("The listing spec must not be null");
		}
		this.listingSpec = listingSpec;
	}
	
	
	/**
	 * Returns the issuer.
	 *
	 * @return The issuer.
	 */
	public Issuer getIssuer() {
		return issuer;
	}
	
	
	/**
	 * Returns the federation entity listing spec.
	 *
	 * @return The listing spec.
	 */
	public EntityListingSpec getListingSpec() {
		return listingSpec;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("operation", Collections.singletonList(getOperationType().getValue()));
		params.put("iss", Collections.singletonList(getIssuer().getValue()));
		switch (getListingSpec()) {
			case LEAF_ENTITIES_ONLY:
				params.put("is_leaf", Collections.singletonList("true"));
				break;
			case INTERMEDIATES_ONLY:
				params.put("is_leaf", Collections.singletonList("false"));
				break;
			case ALL:
				// no output
		}
		return params;
	}
	
	
	/**
	 * Parses an entity listing request from the specified query string
	 * parameters.
	 *
	 * @param params The query string parameters. Must not be {@code null}.
	 *
	 * @return The entity listing request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityListingRequest parse(final Map<String, List<String>> params)
		throws ParseException {
		
		String value = MultivaluedMapUtils.getFirstValue(params, "operation");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing operation type");
		}
		if (! OperationType.LISTING.getValue().equals(value)) {
			throw new ParseException("The operation type must be listing");
		}
		
		value = MultivaluedMapUtils.getFirstValue(params, "iss");
		if (value == null) {
			throw new ParseException("Missing iss (issuer) parameter");
		}
		Issuer issuer = new Issuer(value);
		
		value = MultivaluedMapUtils.getFirstValue(params, "is_leaf");
		EntityListingSpec listingSpec = EntityListingSpec.ALL;
		if ("true".equals(value)) {
			listingSpec = EntityListingSpec.LEAF_ENTITIES_ONLY;
		} else if ("false".equals(value)) {
			listingSpec = EntityListingSpec.INTERMEDIATES_ONLY;
		}
		
		return new EntityListingRequest(null, issuer, listingSpec);
	}
	
	
	/**
	 * Parses an entity listing request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The entity listing request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityListingRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.GET);
		EntityListingRequest request = parse(httpRequest.getQueryParameters());
		return new EntityListingRequest(httpRequest.getURI(), request.getIssuer(), request.getListingSpec());
	}
}
