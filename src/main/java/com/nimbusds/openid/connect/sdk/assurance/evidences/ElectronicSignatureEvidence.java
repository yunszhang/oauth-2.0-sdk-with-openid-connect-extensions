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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;


/**
 * Electronic signature used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 5.1.1.5.
 * </ul>
 */
@Immutable
public final class ElectronicSignatureEvidence extends IdentityEvidence {
	
	
	/**
	 * The signature type.
	 */
	private final SignatureType signatureType;
	
	
	/**
	 * The signature issuer.
	 */
	private final Issuer issuer;
	
	
	/**
	 * The signature serial number.
	 */
	private final String serialNumber;
	
	
	/**
	 * The signature creation time.
	 */
	private final DateWithTimeZoneOffset createdAt;
	
	
	/**
	 * Creates a new signature used as identity evidence.
	 *
	 * @param signatureType The signature type. Must not be {@code null}.
	 * @param issuer        The signature issuer, {@code null} if not
	 *                      specified.
	 * @param serialNumber  The signature serial number, {@code null} if
	 *                      not specified.
	 * @param createdAt     The signature creation time, {@code null} if
	 *                      not specified.
	 */
	public ElectronicSignatureEvidence(final SignatureType signatureType,
					   final Issuer issuer,
					   final String serialNumber,
					   final DateWithTimeZoneOffset createdAt) {
		
		super(IdentityEvidenceType.ELECTRONIC_SIGNATURE);
		Objects.requireNonNull(signatureType);
		this.signatureType = signatureType;
		this.issuer = issuer;
		this.serialNumber = serialNumber;
		this.createdAt = createdAt;
	}
	
	
	/**
	 * Returns the signature type.
	 *
	 * @return The signature type.
	 */
	public SignatureType getSignatureType() {
		return signatureType;
	}
	
	
	/**
	 * Returns the signature issuer.
	 *
	 * @return The signature issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {
		return issuer;
	}
	
	
	/**
	 * Returns the signature serial number.
	 *
	 * @return The signature serial number string, {@code null} if not
	 *         specified.
	 */
	public String getSerialNumberString() {
		return serialNumber;
	}
	
	
	/**
	 * Returns The signature creation time.
	 *
	 * @return The signature creation time, {@code null} if not specified.
	 */
	public DateWithTimeZoneOffset getCreationTime() {
		return createdAt;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = super.toJSONObject();
		
		o.put("signature_type", getSignatureType().getValue());
		
		if (getIssuer() != null) {
			o.put("issuer", getIssuer().getValue());
		}
		if (getSerialNumberString() != null) {
			o.put("serial_number", getSerialNumberString());
		}
		if (getCreationTime() != null) {
			o.put("created_at", getCreationTime().toISO8601String());
		}
		return o;
	}
	
	
	/**
	 * Parses a new signature evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The signature evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ElectronicSignatureEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.ELECTRONIC_SIGNATURE, jsonObject);
		
		SignatureType signatureType = new SignatureType(JSONObjectUtils.getString(jsonObject, "signature_type"));
		
		Issuer issuer = null;
		if (jsonObject.get("issuer") != null) {
			issuer = new Issuer(JSONObjectUtils.getString(jsonObject, "issuer"));
		}
		
		String serialNumber = JSONObjectUtils.getString(jsonObject, "serial_number", null);
		
		DateWithTimeZoneOffset createdAt = null;
		if (jsonObject.get("created_at") != null) {
			createdAt = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getString(jsonObject, "created_at"));
		}
		
		return new ElectronicSignatureEvidence(signatureType, issuer, serialNumber, createdAt);
	}
}
