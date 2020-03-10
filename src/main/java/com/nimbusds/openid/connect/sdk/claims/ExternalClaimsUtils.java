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

package com.nimbusds.openid.connect.sdk.claims;


import java.util.*;

import net.minidev.json.JSONObject;


/**
 * Aggregated and distributed claims utilities.
 */
class ExternalClaimsUtils {
	
	
	/**
	 * Gets the {@code _claim_sources} JSON objects from the specified
	 * claims set JSON object.
	 *
	 * @param claims The claims set JSON object. May be {@code null}.
	 *
	 * @return The {@code _claims_sources} JSON objects, keyed by source
	 *         ID, {@code null} if none.
	 */
	static Map<String,JSONObject> getExternalClaimSources(final JSONObject claims) {
		
		Object o = claims.get("_claim_sources");
		
		if (! (o instanceof JSONObject)) {
			return null;
		}
		
		JSONObject claimSources = (JSONObject) o;
		
		if (claimSources.isEmpty()) {
			return null;
		}
		
		Map<String,JSONObject> out = new HashMap<>();
		
		for (Map.Entry<String,Object> en: claimSources.entrySet()) {
			
			String sourceID = en.getKey();
			
			Object v = en.getValue();
			if (! (v instanceof JSONObject)) {
				continue; // invalid source spec, skip
			}
			
			JSONObject sourceSpec = (JSONObject) v;
			
			out.put(sourceID, sourceSpec);
		}
		
		if (out.isEmpty()) {
			return null;
		}
		
		return out;
	}
	
	
	/**
	 * Returns the external claim names (aggregated or distributed) for the
	 * specified source.
	 *
	 * @param claims   The claims set JSON object. May be {@code null}.
	 * @param sourceID The source ID. May be {@code null}.
	 *
	 * @return The claim names, empty set if none are found.
	 */
	static Set<String> getExternalClaimNamesForSource(final JSONObject claims, final String sourceID) {
		
		if (claims == null || sourceID == null) {
			return Collections.emptySet();
		}
		
		Object claimNamesObject = claims.get("_claim_names");
		
		if (! (claimNamesObject instanceof JSONObject)) {
			return Collections.emptySet();
		}
		
		JSONObject claimNamesJSONObject = (JSONObject)claimNamesObject;
		
		Set<String> claimNames = new HashSet<>();
		
		for (Map.Entry<String,Object> en: claimNamesJSONObject.entrySet()) {
			
			if (sourceID.equals(en.getValue())) {
				// "_claim_names": {
				//     "address": "src1",
				//     "phone_number": "src1"
				// }
				claimNames.add(en.getKey());
			}
			
			if (en.getValue() instanceof List) {
				// "_claim_names": {
				//    "verified_claims": [ "src1", "src2" ]
				// }
				for (Object item: (List<?>)en.getValue()) {
					if (item instanceof String && sourceID.equals((String)item)) {
						claimNames.add(en.getKey());
					}
				}
			}
		}
		
		return claimNames;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private ExternalClaimsUtils() {}
}
