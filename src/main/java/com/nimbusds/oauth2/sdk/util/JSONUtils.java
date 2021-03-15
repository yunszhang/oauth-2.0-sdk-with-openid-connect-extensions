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


import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.parser.JSONParser;


/**
 * JSON helper methods.
 */
final class JSONUtils {


	/**
	 * Parses a JSON value.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The JSON value.
	 *
	 * @throws ParseException If the string cannot be parsed to a JSON
	 *                        value.
	 */
	public static Object parseJSON(final String s)
		throws ParseException {

		try {
			return new JSONParser(JSONParser.USE_HI_PRECISION_FLOAT | JSONParser.ACCEPT_TAILLING_SPACE).parse(s);
		} catch (net.minidev.json.parser.ParseException e) {
			throw new ParseException("Invalid JSON: " + e.getMessage(), e);
		} catch (NullPointerException e) {
			throw e;
		} catch (Exception e) {
			throw new ParseException("Unexpected exception: " + e.getMessage(), e);
		}
	}
}
