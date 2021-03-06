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

package com.nimbusds.oauth2.sdk.auth;


import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.crypto.utils.ConstantTimeUtils;
import com.nimbusds.jose.util.Base64URL;


/**
 * Secret. The secret value should be {@link #erase erased} when no longer in
 * use.
 */
@Immutable
public class Secret implements Serializable {
	
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * The default byte length of generated secrets.
	 */
	public static final int DEFAULT_BYTE_LENGTH = 32;
	
	
	/**
	 * The secure random generator.
	 */
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	
	
	/**
	 * The secret value.
	 */
	private byte[] value;


	/**
	 * Optional expiration date.
	 */
	private final Date expDate;


	/**
	 * Creates a new secret with the specified value.
	 *
	 * @param value The secret value. May be an empty string. Must be
	 *              UTF-8 encoded and not {@code null}.
	 */
	public Secret(final String value) {

		this(value, null);
	}


	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The secret value. May be an empty string. Must be
	 *                UTF-8 encoded and not {@code null}.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final String value, final Date expDate) {

		this.value = value.getBytes(StandardCharsets.UTF_8);
		this.expDate = expDate;
	}
	
	
	/**
	 * Generates a new secret with a cryptographic random value of the
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the secret value to generate. 
	 *                   Must be greater than one.
	 */
	public Secret(final int byteLength) {

		this(byteLength, null);
	}


	/**
	 * Generates a new secret with a cryptographic random value of the
	 * specified byte length, Base64URL-encoded, and the specified 
	 * expiration date.
	 *
	 * @param byteLength The byte length of the secret value to generate. 
	 *                   Must be greater than one.
	 * @param expDate    The expiration date, {@code null} if not 
	 *                   specified.
	 */
	public Secret(final int byteLength, final Date expDate) {
	
		if (byteLength < 1)
			throw new IllegalArgumentException("The byte length must be a positive integer");
		
		byte[] n = new byte[byteLength];
		
		SECURE_RANDOM.nextBytes(n);

		value = Base64URL.encode(n).toString().getBytes(StandardCharsets.UTF_8);
		
		this.expDate = expDate;
	}
	
	
	/**
	 * Generates a new secret with a cryptographic 256-bit (32-byte) random
	 * value, Base64URL-encoded.
	 */
	public Secret() {

		this(DEFAULT_BYTE_LENGTH);
	}


	/**
	 * Gets the value of this secret.
	 *
	 * @return The value as a UTF-8 encoded string, {@code null} if it has 
	 *         been erased.
	 */
	public String getValue() {

		if (value == null) {
			return null; // value has been erased
		}

		return new String(value, StandardCharsets.UTF_8);
	}
	
	
	/**
	 * Gets the value of this secret.
	 *
	 * @return The value as a byte array, {@code null} if it has 
	 *         been erased.
	 */
	public byte[] getValueBytes() {

		return value;
	}
	
	
	/**
	 * Gets the SHA-256 hash of this secret.
	 *
	 * @return The SHA-256 hash, {@code null} if the secret value has been
	 *         erased.
	 */
	public byte[] getSHA256() {
		
		if (value == null) {
			return null;
		}
		
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			return sha256.digest(value);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}


	/**
	 * Erases of the value of this secret.
	 */
	public void erase() {

		if (value == null) {
			return; // Already erased
		}
		
		Arrays.fill(value, (byte) 0);
		
		value = null;
	}


	/**
	 * Gets the expiration date of this secret.
	 *
	 * @return The expiration date, {@code null} if not specified.
	 */
	public Date getExpirationDate() {

		return expDate;
	}


	/**
	 * Checks is this secret has expired.
	 *
	 * @return {@code true} if the secret has an associated expiration date
	 *         which is in the past (according to the current system time), 
	 *         else returns {@code false}.
	 */
	public boolean expired() {

		if (expDate == null) {
			return false; // never expires
		}

		final Date now = new Date();

		return expDate.before(now);
	}
	
	
	/**
	 * Constant time comparison of the SHA-256 hashes of this and another
	 * secret.
	 *
	 * @param other The other secret. May be {@code null}.
	 *
	 * @return {@code true} if the SHA-256 hashes of the two secrets are
	 *         equal, {@code false} if the hashes don't match or the secret
	 *         values are {@link #erase() erased}.
	 */
	@Deprecated
	public boolean equalsSHA256Based(final Secret other) {
		
		if (other == null) {
			return false;
		}
		
		byte[] thisHash = getSHA256();
		byte[] otherHash = other.getSHA256();
		
		if (thisHash == null || otherHash == null) {
			return false;
		}
		
		return ConstantTimeUtils.areEqual(thisHash, otherHash);
	}
	
	
	/**
	 * Comparison with another secret is constant time, based on the
	 * secrets' {@link #getSHA256() SHA-256 hashes}.
	 *
	 * @param o The other object. May be {@code null}.
	 *
	 * @return {@code true} if both objects are equal, else {@code false}.
	 */
	@Override
	public boolean equals(final Object o) {
		if (this == o) return true;
		if (value == null) return false;
		if (!(o instanceof Secret)) return false;
		Secret otherSecret = (Secret) o;
		return equalsSHA256Based(otherSecret);
	}


	@Override
	public int hashCode() {
		return Arrays.hashCode(value);
	}
}