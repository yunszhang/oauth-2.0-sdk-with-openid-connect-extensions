package com.nimbusds.oauth2.sdk.tokenexchange;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenType;
import com.nimbusds.oauth2.sdk.token.TypelessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.ResourceUtils;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import net.jcip.annotations.Immutable;


/**
 * Implementation of token exchange extension grant type as specified in https://datatracker.ietf.org/doc/html/rfc8693
 */
@Immutable
public class TokenExchangeGrant extends AuthorizationGrant {

  public static final GrantType GRANT_TYPE = GrantType.TOKEN_EXCHANGE;

  /**
   * The optional audiences for token exchange
   */
  private final List<String> audiences;

  /**
   * The optional requested token type for token exchange
   */
  private final TokenType requestedTokenType;

  /**
   * The subject token for token exchange
   */
  private final TypelessToken subjectToken;

  /**
   * The subject token type for token exchange
   */
  private final TokenType subjectTokenType;

  /**
   * The actor token for token exchange
   */
  private final TypelessToken actorToken;

  /**
   * The actor token type for token exchange
   */
  private final TokenType actorTokenType;


  /**
   * Creates a new token exchange grant.
   *
   */
  protected TokenExchangeGrant(List<String> audiences, TokenType requestedTokenType,
      TypelessToken subjectToken, TokenType subjectTokenType,
      TypelessToken actorToken, TokenType actorTokenType) {
    super(GRANT_TYPE);

    this.audiences = audiences;
    this.requestedTokenType = requestedTokenType;

    this.subjectToken = subjectToken;
    this.subjectTokenType = subjectTokenType;

    this.actorToken = actorToken;
    this.actorTokenType = actorTokenType;
  }

  public List<String> getAudiences() {
    return audiences;
  }

  public TokenType getRequestedTokenType() {
    return requestedTokenType;
  }

  public Token getSubjectToken() {
    return subjectToken;
  }

  public TokenType getSubjectTokenType() {
    return subjectTokenType;
  }

  public Token getActorToken() {
    return actorToken;
  }

  public TokenType getActorTokenType() {
    return actorTokenType;
  }

  /**
   * Returns the request body parameters for the authorisation grant.
   *
   * @return The parameters.
   */
  @Override
  public Map<String, List<String>> toParameters() {
    Map<String,List<String>> params = new LinkedHashMap<>();
    params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));

    if (audiences != null) {
      params.put("audience", audiences);
    }

    if (requestedTokenType != null) {
      params.put("requested_token_type", Collections.singletonList(requestedTokenType.toString()));
    }

    params.put("subject_token", Collections.singletonList(subjectToken.getValue()));
    params.put("subject_token_type", Collections.singletonList(subjectTokenType.toString()));

    if (actorToken != null) {
      params.put("actor_token", Collections.singletonList(actorToken.getValue()));
    }
    if (actorTokenType != null) {
      params.put("actor_token_type", Collections.singletonList(actorTokenType.toString()));
    }

    return params;
  }

  private static List<String> parseAudience(Map<String, List<String>> params) {
    List<String> audiences = null;
    List<String> audienceList = params.get("audience");

    if (audienceList != null) {
      audiences = new LinkedList<>();

      for (String audience: audienceList) {
        if (audience == null)
          continue;
        audiences.add(audience);
      }
    }
    return audiences;
  }

  private static TokenType parseTokenType(Map<String, List<String>> params, String key, boolean mandatory) throws ParseException {
    String tokenTypeString = MultivaluedMapUtils.getFirstValue(params, key);

    if (tokenTypeString == null || tokenTypeString.trim().isEmpty()) {
      if (mandatory) {
        String msg = String.format("Missing or empty %s parameter", key);
        throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
      } else {
        return null;
      }
    }

    return new TokenType(tokenTypeString);
  }

  private static TypelessToken parseToken(Map<String, List<String>> params, String key, boolean mandatory) throws ParseException {
    String tokenString = MultivaluedMapUtils.getFirstValue(params, key);

    if (tokenString == null || tokenString.trim().isEmpty()) {
      if (mandatory) {
        String msg = String.format("Missing or empty %s parameter", key);
        throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
      } else {
        return null;
      }
    }

    return new TypelessToken(tokenString);
  }

  public static TokenExchangeGrant parse(final Map<String, List<String>> params) throws ParseException {
    GrantType.ensure(GRANT_TYPE, params);

    List<String> audiences = parseAudience(params);
    TokenType requestedTokenType = parseTokenType(params, "requested_token_type", false);
    TypelessToken subjectToken = parseToken(params, "subject_token", true);
    TokenType subjectTokenType = parseTokenType(params, "subject_token_type", true);
    TypelessToken actorToken = parseToken(params, "actor_token", false);
    TokenType actorTokenType = parseTokenType(params, "actor_token_type", false);

    return new TokenExchangeGrant(audiences, requestedTokenType, subjectToken, subjectTokenType, actorToken,
        actorTokenType);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof TokenExchangeGrant)) return false;
    TokenExchangeGrant that = (TokenExchangeGrant) o;
    return requestedTokenType.equals(that.requestedTokenType) &&
        subjectToken.equals(that.subjectToken) &&
        subjectTokenType.equals(that.subjectTokenType) &&
        Objects.equals(actorToken, that.actorToken) &&
        Objects.equals(actorTokenType, that.actorTokenType);
  }


  @Override
  public int hashCode() {
    return Objects.hash(requestedTokenType, subjectToken, subjectTokenType, actorToken, actorTokenType);
  }
}
