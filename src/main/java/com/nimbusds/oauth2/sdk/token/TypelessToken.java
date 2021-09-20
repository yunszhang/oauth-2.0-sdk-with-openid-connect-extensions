package com.nimbusds.oauth2.sdk.token;

import java.util.Collections;
import java.util.Set;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

/**
 * Introduced to represent tokens without a fixed type, used in TokenExchangeGrant.
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

  @Override
  public Set<String> getParameterNames() {
    return Collections.emptySet();
  }

  @Override
  public JSONObject toJSONObject() {
    return new JSONObject();
  }
}
