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

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;


/**
 * Identity document description.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 4.1.1.1.
 * </ul>
 */
public class IDDocumentDescription implements JSONAware {
	
	
	/**
	 * The type.
	 */
	private final IDDocumentType type;
	
	
	/**
	 * The number.
	 */
	private final String number;
	
	
	/**
	 * The issuer name.
	 */
	private final String issuerName;
	
	
	/**
	 * The issuer country.
	 */
	private final CountryCode issuerCountry;
	
	
	/**
	 * The date of issuance.
	 */
	private final SimpleDate dateOfIssuance;
	
	
	/**
	 * The date of expiry.
	 */
	private final SimpleDate dateOfExpiry;
	
	
	/**
	 * Creates a new identity document description.
	 *
	 * @param type           The type. Must not be {@code null}.
	 * @param number         The number. Must not be {@code null}.
	 * @param issuerName     The issuer name. Must not be {@code null}.
	 * @param issuerCountry  The issuer country. Must not be {@code null}.
	 * @param dateOfIssuance The date of issuance. Must not be
	 *                       {@code null}.
	 * @param dateOfExpiry   The date of expiry. Must not be {@code null}.
	 */
	public IDDocumentDescription(final IDDocumentType type,
				     final String number,
				     final String issuerName,
				     final CountryCode issuerCountry,
				     final SimpleDate dateOfIssuance,
				     final SimpleDate dateOfExpiry) {
		
		if (type == null) {
			throw new IllegalArgumentException("The type must not be null");
		}
		this.type = type;
		
		if (number == null) {
			throw new IllegalArgumentException("The number must not be null");
		}
		this.number = number;
		
		if (issuerName == null) {
			throw new IllegalArgumentException("The issuer name must not be null");
		}
		this.issuerName = issuerName;
		
		if (issuerCountry == null) {
			throw new IllegalArgumentException("The issuer country must not be null");
		}
		this.issuerCountry = issuerCountry;
		
		if (dateOfIssuance == null) {
			throw new IllegalArgumentException("The date of issuance must not be null");
		}
		this.dateOfIssuance = dateOfIssuance;
		
		if (dateOfExpiry == null) {
			throw new IllegalArgumentException("The date of expiry must not be null");
		}
		this.dateOfExpiry = dateOfExpiry;
	}
	
	
	/**
	 * Returns the identity document type.
	 *
	 * @return The identity document type.
	 */
	public IDDocumentType getType() {
		return type;
	}
	
	
	/**
	 * Returns the identity document number.
	 *
	 * @return The identity document number.
	 */
	public String getNumber() {
		return number;
	}
	
	
	/**
	 * Returns the issuer name.
	 *
	 * @return The issuer name.
	 */
	public String getIssuerName() {
		return issuerName;
	}
	
	
	/**
	 * Returns the issuer country.
	 *
	 * @return The issuer country code.
	 */
	public CountryCode getIssuerCountry() {
		return issuerCountry;
	}
	
	
	/**
	 * Returns the date of issuance.
	 *
	 * @return The date of issuance.
	 */
	public SimpleDate getDateOfIssuance() {
		return dateOfIssuance;
	}
	
	
	/**
	 * Returns the date of expiry.
	 *
	 * @return The date of expiry.
	 */
	public SimpleDate getDateOfExpiry() {
		return dateOfExpiry;
	}
	
	
	/**
	 * Returns a JSON object representation of this identity document
	 * description.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("type", getType().getValue());
		o.put("number", getNumber()); // TODO https://bitbucket.org/openid/connect/issues/1123/assurance-4111-id_document-document-number
		JSONObject issuerObject = new JSONObject();
		issuerObject.put("name", getIssuerName());
		issuerObject.put("country", getIssuerCountry().getValue());
		o.put("issuer", issuerObject);
		o.put("date_of_issuance", getDateOfIssuance().toISO8601String());
		o.put("date_of_expiry", getDateOfExpiry().toISO8601String());
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public String toString() {
		return toJSONString();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof IDDocumentDescription)) return false;
		IDDocumentDescription that = (IDDocumentDescription) o;
		return getType().equals(that.getType()) &&
			getNumber().equals(that.getNumber()) &&
			getIssuerName().equals(that.getIssuerName()) &&
			getIssuerCountry().equals(that.getIssuerCountry()) &&
			getDateOfIssuance().equals(that.getDateOfIssuance()) &&
			getDateOfExpiry().equals(that.getDateOfExpiry());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getNumber(), getIssuerName(), getIssuerCountry(), getDateOfIssuance(), getDateOfExpiry());
	}
	
	
	/**
	 * Parses an identity document description from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity document description.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDDocumentDescription parse(final JSONObject jsonObject)
		throws ParseException {
		
		IDDocumentType type = new IDDocumentType(JSONObjectUtils.getString(jsonObject, "type"));
		String number = JSONObjectUtils.getString(jsonObject, "number");
		
		JSONObject issuerObject = JSONObjectUtils.getJSONObject(jsonObject, "issuer");
		String issuerName = JSONObjectUtils.getString(issuerObject, "name");
		CountryCode issuerCountry = ISO3166_1Alpha2CountryCode.parse(JSONObjectUtils.getString(issuerObject, "country"));
		
		SimpleDate dateOfIssuance = SimpleDate.parseISO8601String(JSONObjectUtils.getString(jsonObject, "date_of_issuance"));
		SimpleDate dateOfExpiry = SimpleDate.parseISO8601String(JSONObjectUtils.getString(jsonObject, "date_of_expiry"));
		
		return new IDDocumentDescription(type, number, issuerName, issuerCountry, dateOfIssuance, dateOfExpiry);
	}
}
