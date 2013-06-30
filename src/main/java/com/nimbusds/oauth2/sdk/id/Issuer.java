package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Issuer identifier. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class Issuer extends Identifier {


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The issuer identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Issuer(final String value) {

		super(value);
	}


	/**
	 * Creates a new issuer identifier with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Issuer(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new issuer identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Issuer() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof Issuer && 
		       this.toString().equals(object.toString());
	}
}