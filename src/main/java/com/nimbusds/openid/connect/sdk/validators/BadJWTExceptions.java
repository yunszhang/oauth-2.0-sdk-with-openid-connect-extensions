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

package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jwt.proc.BadJWTException;
import net.jcip.annotations.Immutable;


/**
 * Common bad JWT exceptions.
 */
@Immutable
final class BadJWTExceptions {
	
	
	/**
	 * Missing {@code exp} claim exception.
	 */
	static final BadJWTException MISSING_EXP_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT expiration (exp) claim");
	
	
	/**
	 * Missing {@code iat} claim exception.
	 */
	static final BadJWTException MISSING_IAT_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issue time (iat) claim");
	
	
	/**
	 * Missing {@code iss} claim exception.
	 */
	static final BadJWTException MISSING_ISS_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issuer (iss) claim");
	
	
	/**
	 * Missing {@code sub} claim exception.
	 */
	static final BadJWTException MISSING_SUB_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT subject (sub) claim");
	
	
	/**
	 * Missing {@code aud} claim exception.
	 */
	static final BadJWTException MISSING_AUD_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT audience (aud) claim");
	
	
	/**
	 * Missing {@code nonce} claim exception.
	 */
	static final BadJWTException MISSING_NONCE_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT nonce (nonce) claim");
	
	
	/**
	 * Expired ID token exception.
	 */
	static final BadJWTException EXPIRED_EXCEPTION =
		new BadJWTException("Expired JWT");
	
	
	/**
	 * ID token issue time ahead of current time exception.
	 */
	static final BadJWTException IAT_CLAIM_AHEAD_EXCEPTION =
		new BadJWTException("JWT issue time ahead of current time");
	
	
	/**
	 * Prevents public instantiation.
	 */
	private BadJWTExceptions() {}
}
