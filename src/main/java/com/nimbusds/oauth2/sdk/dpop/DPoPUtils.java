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

package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * DPoP utilities.
 */
final class DPoPUtils {
	
	
	/**
	 * Creates a new DPoP JWT claims set.
	 *
	 * @param jti The JWT ID. Must not be {@code null}.
	 * @param htm The HTTP request method. Must not be {@code null}.
	 * @param htu The HTTP URI, without a query or fragment. Must not be
	 *            {@code null}.
	 * @param iat The issue time. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 */
	static JWTClaimsSet createJWTClaimsSet(final JWTID jti,
					       final String htm,
					       final URI htu,
					       final Date iat) {
		
		if (StringUtils.isBlank(htm)) {
			throw new IllegalArgumentException("The HTTP method (htu) is required");
		}
		
		if (htu.getQuery() != null) {
			throw new IllegalArgumentException("The HTTP URI (htu) must not have a query");
		}
		
		if (htu.getFragment() != null) {
			throw new IllegalArgumentException("The HTTP URI (htu) must not have a fragment");
		}
		
		if (iat == null) {
			throw new IllegalArgumentException("The issue time (iat) is required");
		}
		
		return new JWTClaimsSet.Builder()
			.jwtID(jti.getValue())
			.claim("htm", htm)
			.claim("htu", htu.toString())
			.issueTime(iat)
			.build();
	}
	
	
      /**
       *Prevents public instantiation.
       */
      private DPoPUtils() {}
}
