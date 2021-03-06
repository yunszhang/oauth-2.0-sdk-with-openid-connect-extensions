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


import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.ContentTypeUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;


/**
 * The base abstract class for HTTP requests and responses.
 */
abstract class HTTPMessage {


	/**
	 * The HTTP request / response headers.
	 */
	private final Map<String,List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
	
	
	/**
	 * The client IP address.
	 */
	private String clientIPAddress;
	
	
	/**
	 * Gets the {@code Content-Type} header value.
	 *
	 * @return The {@code Content-Type} header value, {@code null} if not
	 *         specified or parsing failed.
	 */
	public ContentType getEntityContentType() {
		
		final String value = getHeaderValue("Content-Type");
		
		if (value == null) {
			return null;
		}
		
		try {
			return ContentType.parse(value);
			
		} catch (java.text.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 */
	public void setEntityContentType(final ContentType ct) {
		
		setHeader("Content-Type", ct != null ? ct.toString() : null);
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 *
	 * @throws ParseException If the header value couldn't be parsed to a
	 *                        valid content type.
	 */
	public void setContentType(final String ct)
		throws ParseException {
		
		try {
			setHeader("Content-Type", ct != null ? ContentType.parse(ct).toString() : null);
			
		} catch (java.text.ParseException e) {
			
			throw new ParseException("Invalid Content-Type value: " + e.getMessage());
		}
	}
	
	
	/**
	 * Ensures this HTTP message has a {@code Content-Type} header value.
	 *
	 * @throws ParseException If the {@code Content-Type} header is 
	 *                        missing.
	 */
	public void ensureEntityContentType()
		throws ParseException {
	
		if (getEntityContentType() == null) {
			throw new ParseException("Missing HTTP Content-Type header");
		}
	}


	/**
	 * Ensures this HTTP message has the specified {@code Content-Type} 
	 * header value. This method compares only the primary type and 
	 * subtype; any content type parameters, such as {@code charset}, are
	 * ignored.
	 *
	 * @param contentType The expected content type. Must not be 
	 *                    {@code null}.
	 *
	 * @throws ParseException If the {@code Content-Type} header is missing
	 *                        or its primary and subtype don't match.
	 */
	public void ensureEntityContentType(final ContentType contentType)
		throws ParseException {
		
		ContentTypeUtils.ensureContentType(contentType, getEntityContentType());
	}


	/**
	 * Gets an HTTP header's value.
	 *
	 * @param name The header name. Must not be {@code null}.
	 *
	 * @return The first header value, {@code null} if not specified.
	 */
	public String getHeaderValue(final String name) {

		return MultivaluedMapUtils.getFirstValue(headers, name);
	}


	/**
	 * Gets an HTTP header's value(s).
	 *
	 * @param name The header name. Must not be {@code null}.
	 *
	 * @return The header value(s), {@code null} if not specified.
	 */
	public List<String> getHeaderValues(final String name) {

		return headers.get(name);
	}


	/**
	 * Sets an HTTP header.
	 *
	 * @param name   The header name. Must not be {@code null}.
	 * @param values The header value(s). If {@code null} and a header with
	 *               the same name is specified, it will be deleted.
	 */
	public void setHeader(final String name, final String ... values) {

		if (values != null && values.length > 0) {
			headers.put(name, Arrays.asList(values));
		} else {
			headers.remove(name);
		}
	}


	/**
	 * Returns the HTTP headers.
	 *
	 * @return The HTTP headers.
	 */
	public Map<String,List<String>> getHeaderMap() {

		return headers;
	}
	
	
	/**
	 * Gets the client IP address.
	 *
	 * @return The client IP address, {@code null} if not specified.
	 */
	public String getClientIPAddress() {
		
		return clientIPAddress;
	}
	
	
	/**
	 * Sets the client IP address.
	 *
	 * @param clientIPAddress The client IP address, {@code null} if not
	 *                        specified.
	 */
	public void setClientIPAddress(final String clientIPAddress) {
		
		this.clientIPAddress = clientIPAddress;
	}
}