package com.nimbusds.oauth2.sdk.token;

import java.util.Collections;
import java.util.Set;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

/**
 * Introduced to represent tokens without explicity used in TokenExchangeGrant
 */
@Immutable
public class TypelessToken extends Token {

  /**
   * Creates a new typeless token with the specified value.
   *
   * @param value The token value. Must not be {@code null} or empty string.
   */
  public TypelessToken(String value) {
    super(value);
  }

  /**
   * Creates a new typeless token with a randomly generated value of the specified byte length, Base64URL-encoded.
   *
   * @param byteLength The byte length of the value to generate. Must be greater than one.
   */
  public TypelessToken(int byteLength) {
    super(byteLength);
  }

  /**
   * Creates a new typeless token with a randomly generated 256-bit (32-byte) value, Base64URL-encoded.
   */
  public TypelessToken() {
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
