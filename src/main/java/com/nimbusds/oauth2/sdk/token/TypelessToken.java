package com.nimbusds.oauth2.sdk.token;


import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * Typeless (generic) token.
 */
@Immutable
public class TypelessToken extends Token {
	
	
	private static final long serialVersionUID = 1477117093355749547L;
	
	
	/**
	 * Creates a new typeless token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty
	 *              string.
	 */
	public TypelessToken(final String value) {
		super(value);
	}
	
	
	@Override
	public Set<String> getParameterNames() {
		return Collections.emptySet();
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		return new JSONObject();
	}
}
