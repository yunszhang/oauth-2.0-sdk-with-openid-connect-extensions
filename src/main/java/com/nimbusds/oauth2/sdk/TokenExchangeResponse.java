package com.nimbusds.oauth2.sdk;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;
import org.opensaml.soap.wsaddressing.To;

/**
 * Token exchange response from the Token endpoint.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-cache, no-store
 *
 * {
 *   "access_token":"eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJo
 *     dHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL2FzLmV
 *     4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsIn
 *     N1YiI6ImJkY0BleGFtcGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rx
 *     f59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCM
 *     y5-kdXjwhw",
 *   "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
 *   "token_type":"Bearer",
 *   "expires_in":60
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Exchange (RFC 8693), sections 2.2.1 and 2.3.
 * </ul>
 */
@Immutable
public class TokenExchangeResponse extends AccessTokenResponse {

  /**
   * Issued token type
   */
  private final TokenTypeURI issuedTokenType;

  /**
   * Optional scope of issued token
   */
  private final Scope scope;

  /**
   * Creates a new access token response.
   *
   * @param tokens The tokens. Must not be {@code null}.
   * @param issuedTokenType Issued token type. Must not be {@code null}.
   * @param scope Scope of issued token. Can be {@code null}.
   */
  public TokenExchangeResponse(Tokens tokens, TokenTypeURI issuedTokenType, Scope scope) {
    super(tokens);
    if (issuedTokenType == null) {
      throw new IllegalArgumentException("Issued token type must not be null");
    }
    this.issuedTokenType = issuedTokenType;
    this.scope = scope;
  }

  /**
   * Creates a new access token response.
   *
   * @param tokens The tokens. Must not be {@code null}.
   * @param customParams Optional custom parameters, {@code null} if
   */
  public TokenExchangeResponse(Tokens tokens, Map<String, Object> customParams, TokenTypeURI issuedTokenType, Scope scope) {
    super(tokens, customParams);
    this.issuedTokenType = issuedTokenType;
    this.scope = scope;
  }

  public TokenTypeURI getIssuedTokenType() {
    return issuedTokenType;
  }

  public Scope getScope() {
    return scope;
  }

  /**
   * Returns a JSON object representation of this OpenID Connect token
   * response.
   *
   * <p>Example JSON object:
   *
   * <pre>
   * {
   *   "access_token":"eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJo
   *     dHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL2FzLmV
   *     4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsIn
   *     N1YiI6ImJkY0BleGFtcGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rx
   *     f59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCM
   *     y5-kdXjwhw",
   *   "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
   *   "token_type":"Bearer",
   *   "expires_in":60
   * }
   * </pre>
   *
   * @return The JSON object.
   */
  @Override
  public JSONObject toJSONObject() {
    JSONObject o = super.toJSONObject();
    o.put("issued_token_type", issuedTokenType.getURI().toString());
    if (scope != null) {
      o.put("scope", scope.toString());
    }
    return o;
  }

  /**
   * Parses a Token Exchange response from the specified JSON
   * object.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   {@code null}.
   *
   * @return The Token Exchange response.
   *
   * @throws ParseException If the JSON object couldn't be parsed to an
   *                        OpenID Connect token response.
   */
  public static TokenExchangeResponse parse(final JSONObject jsonObject) throws ParseException {

    Tokens tokens = Tokens.parse(jsonObject);

    TokenTypeURI issuedTokenType = null;
    try {
      issuedTokenType = TokenTypeURI.parse(jsonObject.getAsString("issued_token_type"));
    } catch (URISyntaxException uriSyntaxException) {
      throw new ParseException("Invalid issued token type!", uriSyntaxException);
    }
    String scopeString = jsonObject.getAsString("scope");
    Scope scope = null;
    if (scopeString != null) {
      scope = Scope.parse(scopeString);
    }

    Map<String, Object> customParams = new HashMap<>(jsonObject);
    for (String tokenParam : tokens.getParameterNames()) {
      customParams.remove(tokenParam);
    }
    customParams.remove("issued_token_type");
    customParams.remove("scope");

    if (customParams.isEmpty()) {
      return new TokenExchangeResponse(tokens, issuedTokenType, scope);
    } else {
      return new TokenExchangeResponse(tokens, customParams, issuedTokenType, scope);
    }
  }

  /**
   * Parses a Token Exchange response from the specified
   * HTTP response.
   *
   * @param httpResponse The HTTP response. Must not be {@code null}.
   *
   * @return The Token Exchange response.
   *
   * @throws ParseException If the HTTP response couldn't be parsed to an
   *                        OpenID Connect access token response.
   */
  public static TokenExchangeResponse parse(final HTTPResponse httpResponse)
      throws ParseException {

    httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
    JSONObject jsonObject = httpResponse.getContentAsJSONObject();
    return parse(jsonObject);
  }
}
