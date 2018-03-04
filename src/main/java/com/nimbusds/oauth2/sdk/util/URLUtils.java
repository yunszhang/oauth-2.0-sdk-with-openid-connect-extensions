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


import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;


/**
 * URL operations.
 */
public class URLUtils {

	
	/**
	 * The default UTF-8 character set.
	 */
	public static final String CHARSET = "utf-8";
	
	
	/**
	 * Gets the base part (protocol, host, port and path) of the specified
	 * URL.
	 *
	 * @param url The URL. May be {@code null}.
	 *
	 * @return The base part of the URL, {@code null} if the original URL 
	 *         is {@code null} or doesn't specify a protocol.
	 */
	public static URL getBaseURL(final URL url) {
	
		if (url == null)
			return null;
		
		try {
			return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
			
		} catch (MalformedURLException e) {
		
			return null;
		}
	}
	
	
	/**
	 * Serialises the specified map of parameters into a URL query string. 
	 * The parameter keys and values are 
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests is not included in the returned string.
	 *
	 * <p>Example query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * <p>The opposite method is {@link #parseParameters}.
	 *
	 * @param params A map of the URL query parameters. May be empty or
	 *               {@code null}.
	 *
	 * @return The serialised URL query string, empty if no parameters.
	 */
	public static String serializeParameters(final Map<String,String> params) {
	
		if (params == null || params.isEmpty())
			return "";
		
		StringBuilder sb = new StringBuilder();
		
		for (Map.Entry<String,String> entry: params.entrySet()) {
			
			if (entry.getKey() == null)
				continue;

			String value = entry.getValue() != null ? entry.getValue() : "";
			
			try {
				String encodedKey = URLEncoder.encode(entry.getKey(), CHARSET);
				String encodedValue = URLEncoder.encode(value, CHARSET);
				
				if (sb.length() > 0)
					sb.append('&');
				
				sb.append(encodedKey);
				sb.append('=');
				sb.append(encodedValue);
	
			} catch (UnsupportedEncodingException e) {

				// UTF-8 should always be supported
				throw new RuntimeException(e.getMessage(), e);
			}
		}
		
		return sb.toString();
	}


	/**
	 * Serialises the specified map of parameters into a URL query string.
	 * Supports multiple key / value pairs that have the same key. The
	 * parameter keys and values are
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests is not included in the returned string.
	 *
	 * <p>Example query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * <p>The opposite method is {@link #parseParameters}.
	 *
	 * @param params A map of the URL query parameters. May be empty or
	 *               {@code null}.
	 *
	 * @return The serialised URL query string, empty if no parameters.
	 */
	public static String serializeParametersAlt(final Map<String,String[]> params) {

		if (params == null || params.isEmpty())
			return "";

		StringBuilder sb = new StringBuilder();

		for (Map.Entry<String,String[]> entry: params.entrySet()) {

			if (entry.getKey() == null || entry.getValue() == null)
				continue;

			for (String value: entry.getValue()) {

				if (value == null)
					value = "";

				try {
					String encodedKey = URLEncoder.encode(entry.getKey(), CHARSET);
					String encodedValue = URLEncoder.encode(value, CHARSET);

					if (sb.length() > 0)
						sb.append('&');

					sb.append(encodedKey);
					sb.append('=');
					sb.append(encodedValue);

				} catch (UnsupportedEncodingException e) {

					// UTF-8 should always be supported
					throw new RuntimeException(e.getMessage(), e);
				}
			}
		}

		return sb.toString();
	}


	/**
	 * Parses the specified URL query string into a parameter map. If a 
	 * parameter has multiple values only the first one will be saved. The
	 * parameter keys and values are 
	 * {@code application/x-www-form-urlencoded} decoded.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests must not be included.
	 *
	 * <p>Example query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * <p>The opposite method {@link #serializeParameters}.
	 *
	 * @param query The URL query string to parse. May be {@code null}.
	 *
	 * @return A map of the URL query parameters, empty if none are found.
	 */
	public static Map<String,String> parseParameters(final String query) {
		
		Map<String,String> params = new HashMap<>();
		
		if (StringUtils.isBlank(query)) {
			return params; // empty map
		}
		
		try {
			StringTokenizer st = new StringTokenizer(query.trim(), "&");

			while(st.hasMoreTokens()) {

				String param = st.nextToken();

				String pair[] = param.split("=", 2); // Split around the first '=', see issue #169

				String key = URLDecoder.decode(pair[0], CHARSET);
				
				// Save the first value only
				if (params.containsKey(key))
					continue;

				String value = "";

				if (pair.length > 1) {
					value = URLDecoder.decode(pair[1], CHARSET);
				}
				
				params.put(key, value);
			}
			
		} catch (UnsupportedEncodingException e) {
			
			// UTF-8 should always be supported
		}
		
		return params;
	}


	/**
	 * Prevents instantiation.
	 */
	private URLUtils() {
	
		// do nothing
	}
}
