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


import javax.mail.internet.ContentType;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Content type matching.
 */
public class ContentTypeUtils {


	/**
	 * Ensures the content type of an HTTP header matches an expected 
	 * value. Note that this method compares only the primary type and 
	 * subtype; any content type parameters, such as {@code charset}, are 
	 * ignored.
	 *
	 * @param expected The expected content type. Must not be {@code null}.
	 * @param found    The found content type. May be {@code null}.
	 *
	 * @throws ParseException If the found content type is {@code null} or
	 *                        it primary and subtype and doesn't match the
	 *                        expected.
	 */
	public static void ensureContentType(final ContentType expected, final ContentType found)
		throws ParseException {
	
		if (found == null)
			throw new ParseException("Missing HTTP Content-Type header");
		
		if (! expected.match(found))
			throw new ParseException("The HTTP Content-Type header must be " + expected);
	}
	

	/**
	 * Prevents instantiation.
	 */
	private ContentTypeUtils() {
	
		// do nothing
	}
}
