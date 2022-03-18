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


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Resource server URI utilities.
 */
public final class ResourceUtils {
	
	
	/**
	 * Returns {@code true} if the specified resource URI is valid.
	 *
	 * @param resourceURI The resource URI. Must not be {@code null}.
	 *
	 * @return {@code true} if the resource URI is valid, {@code false} if
	 *         the URI is not absolute or has a fragment.
	 *
	 * @deprecated Use {@link #isLegalResourceURI} instead.
	 */
	@Deprecated
	public static boolean isValidResourceURI(final URI resourceURI) {
		
		return isLegalResourceURI(resourceURI);
	}
	
	
	/**
	 * Returns {@code true} if the specified resource URI is legal.
	 *
	 * @param resourceURI The resource URI, {@code null} if not specified.
	 *
	 * @return {@code true} if the resource URI is legal or {@code null},
	 *         {@code false} if the URI is not absolute or has a fragment.
	 */
	public static boolean isLegalResourceURI(final URI resourceURI) {
		
		return resourceURI == null || (resourceURI.isAbsolute() && resourceURI.getFragment() == null);
	}
	
	
	/**
	 * Ensures the specified resource URIs are legal.
	 *
	 * @param resourceURIs The resource URIs, {@code null} if not
	 *                     specified.
	 *
	 * @return The checked resource URIs, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the resource URIs are not legal
	 *                                  according to
	 *                                  {@link #isLegalResourceURI}.
	 */
	public static List<URI> ensureLegalResourceURIs(final List<URI> resourceURIs) {
		
		if (CollectionUtils.isEmpty(resourceURIs))
			return resourceURIs;
		
		for (URI resourceURI: resourceURIs) {
			
			if (resourceURI == null)
				continue; // skip
			
			if (! ResourceUtils.isValidResourceURI(resourceURI))
				throw new IllegalArgumentException("Resource URI must be absolute and without a fragment: " + resourceURI);
		}
		
		return resourceURIs;
	}
	
	
	/**
	 * Parses a list of resource URIs from the specified string list.
	 *
	 * @param stringList The string list, {@code null} if not specified.
	 *
	 * @return The resource URIs, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static List<URI> parseResourceURIs(final List<String> stringList)
		throws ParseException {
		
		if (CollectionUtils.isEmpty(stringList)) {
			return null;
		}
		
		List<URI> resources = new LinkedList<>();
		
		for (String uriValue: stringList) {
			
			if (uriValue == null)
				continue;
			
			String errMsg = "Illegal resource parameter: Must be an absolute URI and with no query or fragment";
			
			URI resourceURI;
			try {
				resourceURI = new URI(uriValue);
			} catch (URISyntaxException e) {
				throw new ParseException(errMsg);
			}
			
			if (! ResourceUtils.isLegalResourceURI(resourceURI)) {
				throw new ParseException(errMsg);
			}
			
			resources.add(resourceURI);
		}
		
		return Collections.unmodifiableList(resources);
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private ResourceUtils() {}
}
