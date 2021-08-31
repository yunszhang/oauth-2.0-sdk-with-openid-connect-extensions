package com.nimbusds.oauth2.sdk.token;

import com.nimbusds.oauth2.sdk.id.Identifier;

/**
 * Introduced to represent token types used in TokenExchangeGrant
 */
public final class TokenType extends Identifier {

  private static final long serialVersionUID = 4537977573521742634L;

  /**
   * Indicates that the token is an OAuth 2.0 access token issued by the given
   * authorization server.
   */
  public static final TokenType ACCESS_TOKEN = new TokenType("urn:ietf:params:oauth:token-type:access_token");

  /**
   * Indicates that the token is an OAuth 2.0 refresh token issued by the given
   * authorization server.
   */
  public static final TokenType REFRESH_TOKEN = new TokenType("urn:ietf:params:oauth:token-type:refresh_token");

  /**
   * Indicates that the token is an ID Token as defined in Section 2 of OpenID.Core.
   */
  public static final TokenType ID_TOKEN = new TokenType("urn:ietf:params:oauth:token-type:id_token");

  /**
   *  Indicates that the token is a base64url-encoded SAML 1.1
   *  OASIS.saml-core-1.1 assertion.
   */
  public static final TokenType SAML1 = new TokenType("urn:ietf:params:oauth:token-type:saml1");

  /**
   *  Indicates that the token is a base64url-encoded SAML 2.0
   *  OASIS.saml-core-2.0-os assertion.
   */
  public static final TokenType SAML2 = new TokenType("urn:ietf:params:oauth:token-type:saml2");

  /**
   * Creates a new identifier with the specified value.
   *
   * @param value The identifier value. Must not be {@code null} or empty string.
   */
  public TokenType(String value) {
    super(value);
  }


  @Override
  public boolean equals(Object object) {
    return object instanceof TokenType &&
        this.toString().equalsIgnoreCase(object.toString());
  }
}
