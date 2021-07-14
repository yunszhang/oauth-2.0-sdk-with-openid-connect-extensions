/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;


/**
 * DPoP proof JWT single use checker. Caches a hash of the checked DPoP JWT
 * "jti" (JWT ID) claims for a given DPoP issuer. The checker should be
 * {@link #shutdown() shut down} when no longer in use.
 */
@ThreadSafe
public class DefaultDPoPSingleUseChecker implements SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> {
	
	private final Timer timer;
	
	private final ConcurrentHashMap<String,Long> cachedJTIs = new ConcurrentHashMap<>();
	
	
	/**
	 * Creates a new DPoP proof JWT single use checker.
	 *
	 * @param lifetimeSeconds      The lifetime of cached DPoP proof "jti"
	 *                             (JWT ID) claims, in seconds.
	 * @param purgeIntervalSeconds The interval in seconds for purging the
	 *                             cached "jti" (JWT ID) claims of checked
	 *                             DPoP proofs.
	 */
	public DefaultDPoPSingleUseChecker(final long lifetimeSeconds,
					   final long purgeIntervalSeconds) {
		
		timer = new Timer("dpop-single-use-jti-cache-purge-task", true);
		
		timer.schedule(
			new TimerTask() {
				@Override
				public void run() {
					final long nowMS = new Date().getTime();
					final long expHorizon = nowMS - lifetimeSeconds * 1000;
					for (Map.Entry<String, Long> en: cachedJTIs.entrySet()) {
						if (en.getValue() < expHorizon) {
							cachedJTIs.remove(en.getKey());
						}
					}
				}
			},
			purgeIntervalSeconds * 1000,
			purgeIntervalSeconds * 1000);
	}
	
	
	/**
	 * Computes a SHA-256 hash for the specified access token.
	 *
	 * @param jti The access token. Must not be {@code null}.
	 *
	 * @return The hash, BASE64 URL encoded.
	 *
	 * @throws RuntimeException If hashing failed.
	 */
	private static Base64URL computeSHA256(final JWTID jti) {
		
		byte[] hash;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			hash = md.digest(jti.getValue().getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
		
		return Base64URL.encode(hash);
	}
	
	
	@Override
	public void markAsUsed(final Map.Entry<DPoPIssuer, JWTID> object)
		throws AlreadyUsedException {
		
		String key = object.getKey().getValue() + ":" + computeSHA256(object.getValue());
		
		long nowMS = new Date().getTime();
		
		if (cachedJTIs.putIfAbsent(key, nowMS) != null) {
			throw new AlreadyUsedException("Detected jti replay");
		}
	}
	
	
	/**
	 * Returns the number of cached items.
	 *
	 * @return The cached items, zero if none.
	 */
	public int getCacheSize() {
		
		return cachedJTIs.size();
	}
	
	
	/**
	 * Shuts down this checker and frees any associated resources.
	 */
	public void shutdown() {
		
		timer.cancel();
	}
}
