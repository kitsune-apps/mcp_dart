/// OAuth 2.1 types and metadata structures for MCP authentication.
///
/// This library contains all OAuth-related type definitions including:
/// - Token structures
/// - Client metadata and information
/// - Protected resource metadata (RFC 9728)
/// - Authorization server metadata (RFC 8414 / OIDC Discovery)
/// - Error types
library;

/// Represents OAuth 2.1 tokens obtained from authorization.
class OAuthTokens {
  /// The access token used to authenticate requests.
  final String accessToken;

  /// Optional refresh token used to obtain new access tokens.
  final String? refreshToken;

  /// Token type, typically "Bearer".
  final String? tokenType;

  /// Number of seconds until the access token expires.
  final int? expiresIn;

  /// The scope(s) granted by this token.
  final String? scope;

  /// Timestamp (in milliseconds since epoch) when these tokens were issued.
  /// Used to calculate expiration time.
  final int issuedAt;

  OAuthTokens({
    required this.accessToken,
    this.refreshToken,
    this.tokenType,
    this.expiresIn,
    this.scope,
    int? issuedAt,
  }) : issuedAt = issuedAt ?? DateTime.now().millisecondsSinceEpoch;

  factory OAuthTokens.fromJson(Map<String, dynamic> json) {
    return OAuthTokens(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String?,
      tokenType: json['token_type'] as String?,
      expiresIn: json['expires_in'] as int?,
      scope: json['scope'] as String?,
      issuedAt: json['issued_at'] as int?,
    );
  }

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        if (refreshToken != null) 'refresh_token': refreshToken,
        if (tokenType != null) 'token_type': tokenType,
        if (expiresIn != null) 'expires_in': expiresIn,
        if (scope != null) 'scope': scope,
        'issued_at': issuedAt,
      };

  /// Returns the expiration time as a DateTime, or null if expiry is unknown.
  DateTime? get expiresAt {
    if (expiresIn == null) return null;
    return DateTime.fromMillisecondsSinceEpoch(issuedAt)
        .add(Duration(seconds: expiresIn!));
  }

  /// Checks if the access token is currently expired.
  bool get isExpired {
    final expiry = expiresAt;
    if (expiry == null) return false; // Unknown expiry = assume valid
    return DateTime.now().isAfter(expiry);
  }

  /// Checks if the access token will expire soon.
  ///
  /// Returns true if the token will expire within the specified [buffer] duration.
  /// Default buffer is 5 minutes.
  bool willExpireSoon([Duration buffer = const Duration(minutes: 5)]) {
    final expiry = expiresAt;
    if (expiry == null) return false; // Unknown expiry = assume valid
    return DateTime.now().add(buffer).isAfter(expiry);
  }

  /// Creates a copy of this token with updated values.
  OAuthTokens copyWith({
    String? accessToken,
    String? refreshToken,
    String? tokenType,
    int? expiresIn,
    String? scope,
    int? issuedAt,
  }) {
    return OAuthTokens(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      tokenType: tokenType ?? this.tokenType,
      expiresIn: expiresIn ?? this.expiresIn,
      scope: scope ?? this.scope,
      issuedAt: issuedAt ?? this.issuedAt,
    );
  }
}

/// Metadata about the OAuth client for registration.
class OAuthClientMetadata {
  /// Human-readable name of the client.
  final String? clientName;

  /// Array of redirect URIs for authorization callbacks.
  final List<String> redirectUris;

  /// OAuth 2.1 grant types the client will use.
  final List<String> grantTypes;

  /// OAuth 2.1 response types the client expects.
  final List<String> responseTypes;

  /// Space-separated scope string the client may request.
  final String? scope;

  /// Optional client URI for more information.
  final String? clientUri;

  /// Optional logo URI.
  final String? logoUri;

  /// Optional contacts list.
  final List<String>? contacts;

  /// Optional terms of service URI.
  final String? tosUri;

  /// Optional privacy policy URI.
  final String? policyUri;

  const OAuthClientMetadata({
    this.clientName,
    required this.redirectUris,
    this.grantTypes = const ['authorization_code', 'refresh_token'],
    this.responseTypes = const ['code'],
    this.scope,
    this.clientUri,
    this.logoUri,
    this.contacts,
    this.tosUri,
    this.policyUri,
  });

  Map<String, dynamic> toJson() => {
        if (clientName != null) 'client_name': clientName,
        'redirect_uris': redirectUris,
        'grant_types': grantTypes,
        'response_types': responseTypes,
        if (scope != null) 'scope': scope,
        if (clientUri != null) 'client_uri': clientUri,
        if (logoUri != null) 'logo_uri': logoUri,
        if (contacts != null) 'contacts': contacts,
        if (tosUri != null) 'tos_uri': tosUri,
        if (policyUri != null) 'policy_uri': policyUri,
      };
}

/// Base class for OAuth client information.
///
/// Use [OAuthClientInformationFull] for complete registration data,
/// or [OAuthClientInformationPartial] for minimal (client_id only) data.
sealed class OAuthClientInformation {
  /// The client identifier issued by the authorization server.
  String get clientId;

  /// Optional client secret for confidential clients.
  String? get clientSecret;

  const OAuthClientInformation();

  factory OAuthClientInformation.fromJson(Map<String, dynamic> json) {
    if (json.containsKey('client_id_issued_at') ||
        json.containsKey('client_secret_expires_at') ||
        json.containsKey('registration_access_token') ||
        json.containsKey('registration_client_uri')) {
      return OAuthClientInformationFull.fromJson(json);
    }
    return OAuthClientInformationPartial.fromJson(json);
  }

  Map<String, dynamic> toJson();
}

/// Partial OAuth client information (minimal data).
class OAuthClientInformationPartial extends OAuthClientInformation {
  @override
  final String clientId;

  @override
  final String? clientSecret;

  /// Optional token endpoint authentication method returned by server.
  final String? tokenEndpointAuthMethod;

  const OAuthClientInformationPartial({
    required this.clientId,
    this.clientSecret,
    this.tokenEndpointAuthMethod,
  });

  factory OAuthClientInformationPartial.fromJson(Map<String, dynamic> json) {
    return OAuthClientInformationPartial(
      clientId: json['client_id'] as String,
      clientSecret: json['client_secret'] as String?,
      tokenEndpointAuthMethod: json['token_endpoint_auth_method'] as String?,
    );
  }

  @override
  Map<String, dynamic> toJson() => {
        'client_id': clientId,
        if (clientSecret != null) 'client_secret': clientSecret,
        if (tokenEndpointAuthMethod != null)
          'token_endpoint_auth_method': tokenEndpointAuthMethod,
      };
}

/// Full OAuth client information from Dynamic Client Registration (RFC 7591).
class OAuthClientInformationFull extends OAuthClientInformation {
  @override
  final String clientId;

  @override
  final String? clientSecret;

  /// Timestamp when the client_id was issued.
  final int? clientIdIssuedAt;

  /// Timestamp when the client_secret expires (0 = never).
  final int? clientSecretExpiresAt;

  /// Token for accessing the client configuration endpoint.
  final String? registrationAccessToken;

  /// URI for the client configuration endpoint.
  final String? registrationClientUri;

  /// Token endpoint authentication method.
  final String? tokenEndpointAuthMethod;

  /// All other metadata from registration response.
  final Map<String, dynamic>? additionalMetadata;

  const OAuthClientInformationFull({
    required this.clientId,
    this.clientSecret,
    this.clientIdIssuedAt,
    this.clientSecretExpiresAt,
    this.registrationAccessToken,
    this.registrationClientUri,
    this.tokenEndpointAuthMethod,
    this.additionalMetadata,
  });

  factory OAuthClientInformationFull.fromJson(Map<String, dynamic> json) {
    return OAuthClientInformationFull(
      clientId: json['client_id'] as String,
      clientSecret: json['client_secret'] as String?,
      clientIdIssuedAt: json['client_id_issued_at'] as int?,
      clientSecretExpiresAt: json['client_secret_expires_at'] as int?,
      registrationAccessToken: json['registration_access_token'] as String?,
      registrationClientUri: json['registration_client_uri'] as String?,
      tokenEndpointAuthMethod: json['token_endpoint_auth_method'] as String?,
      additionalMetadata: Map<String, dynamic>.from(json)
        ..remove('client_id')
        ..remove('client_secret')
        ..remove('client_id_issued_at')
        ..remove('client_secret_expires_at')
        ..remove('registration_access_token')
        ..remove('registration_client_uri')
        ..remove('token_endpoint_auth_method'),
    );
  }

  @override
  Map<String, dynamic> toJson() => {
        'client_id': clientId,
        if (clientSecret != null) 'client_secret': clientSecret,
        if (clientIdIssuedAt != null) 'client_id_issued_at': clientIdIssuedAt,
        if (clientSecretExpiresAt != null)
          'client_secret_expires_at': clientSecretExpiresAt,
        if (registrationAccessToken != null)
          'registration_access_token': registrationAccessToken,
        if (registrationClientUri != null)
          'registration_client_uri': registrationClientUri,
        if (tokenEndpointAuthMethod != null)
          'token_endpoint_auth_method': tokenEndpointAuthMethod,
        ...?additionalMetadata,
      };
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
///
/// Advertises information about the resource server including
/// authorization servers and supported scopes.
class OAuthProtectedResourceMetadata {
  /// The protected resource identifier.
  final String resource;

  /// List of authorization server identifiers.
  final List<String>? authorizationServers;

  /// URI providing human-readable information.
  final String? resourceDocumentation;

  /// Scopes supported by this resource.
  final List<String>? scopesSupported;

  /// Bearer token methods supported.
  final List<String>? bearerMethodsSupported;

  /// Signing algorithms supported for resource indicators.
  final List<String>? resourceSigningAlgValuesSupported;

  /// Additional metadata.
  final Map<String, dynamic>? additionalMetadata;

  const OAuthProtectedResourceMetadata({
    required this.resource,
    this.authorizationServers,
    this.resourceDocumentation,
    this.scopesSupported,
    this.bearerMethodsSupported,
    this.resourceSigningAlgValuesSupported,
    this.additionalMetadata,
  });

  factory OAuthProtectedResourceMetadata.fromJson(Map<String, dynamic> json) {
    return OAuthProtectedResourceMetadata(
      resource: json['resource'] as String,
      authorizationServers:
          (json['authorization_servers'] as List<dynamic>?)?.cast<String>(),
      resourceDocumentation: json['resource_documentation'] as String?,
      scopesSupported:
          (json['scopes_supported'] as List<dynamic>?)?.cast<String>(),
      bearerMethodsSupported:
          (json['bearer_methods_supported'] as List<dynamic>?)?.cast<String>(),
      resourceSigningAlgValuesSupported:
          (json['resource_signing_alg_values_supported'] as List<dynamic>?)
              ?.cast<String>(),
      additionalMetadata: Map<String, dynamic>.from(json)
        ..remove('resource')
        ..remove('authorization_servers')
        ..remove('resource_documentation')
        ..remove('scopes_supported')
        ..remove('bearer_methods_supported')
        ..remove('resource_signing_alg_values_supported'),
    );
  }

  Map<String, dynamic> toJson() => {
        'resource': resource,
        if (authorizationServers != null)
          'authorization_servers': authorizationServers,
        if (resourceDocumentation != null)
          'resource_documentation': resourceDocumentation,
        if (scopesSupported != null) 'scopes_supported': scopesSupported,
        if (bearerMethodsSupported != null)
          'bearer_methods_supported': bearerMethodsSupported,
        if (resourceSigningAlgValuesSupported != null)
          'resource_signing_alg_values_supported':
              resourceSigningAlgValuesSupported,
        ...?additionalMetadata,
      };
}

/// Authorization Server Metadata (RFC 8414 / OIDC Discovery).
///
/// Contains endpoint URIs and capabilities of an authorization server.
class AuthorizationServerMetadata {
  /// The authorization server's issuer identifier.
  final String issuer;

  /// URL of the authorization endpoint.
  final String authorizationEndpoint;

  /// URL of the token endpoint.
  final String tokenEndpoint;

  /// URL of the Dynamic Client Registration endpoint.
  final String? registrationEndpoint;

  /// URL of the token introspection endpoint.
  final String? introspectionEndpoint;

  /// URL of the token revocation endpoint.
  final String? revocationEndpoint;

  /// URL of the JWKs endpoint.
  final String? jwksUri;

  /// Response types supported.
  final List<String> responseTypesSupported;

  /// Grant types supported.
  final List<String>? grantTypesSupported;

  /// Token endpoint authentication methods supported.
  final List<String>? tokenEndpointAuthMethodsSupported;

  /// PKCE code challenge methods supported.
  final List<String>? codeChallengeMethodsSupported;

  /// Scopes supported.
  final List<String>? scopesSupported;

  /// Additional metadata.
  final Map<String, dynamic>? additionalMetadata;

  const AuthorizationServerMetadata({
    required this.issuer,
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    this.registrationEndpoint,
    this.introspectionEndpoint,
    this.revocationEndpoint,
    this.jwksUri,
    required this.responseTypesSupported,
    this.grantTypesSupported,
    this.tokenEndpointAuthMethodsSupported,
    this.codeChallengeMethodsSupported,
    this.scopesSupported,
    this.additionalMetadata,
  });

  factory AuthorizationServerMetadata.fromJson(Map<String, dynamic> json) {
    return AuthorizationServerMetadata(
      issuer: json['issuer'] as String,
      authorizationEndpoint: json['authorization_endpoint'] as String,
      tokenEndpoint: json['token_endpoint'] as String,
      registrationEndpoint: json['registration_endpoint'] as String?,
      introspectionEndpoint: json['introspection_endpoint'] as String?,
      revocationEndpoint: json['revocation_endpoint'] as String?,
      jwksUri: json['jwks_uri'] as String?,
      responseTypesSupported:
          (json['response_types_supported'] as List<dynamic>).cast<String>(),
      grantTypesSupported:
          (json['grant_types_supported'] as List<dynamic>?)?.cast<String>(),
      tokenEndpointAuthMethodsSupported:
          (json['token_endpoint_auth_methods_supported'] as List<dynamic>?)
              ?.cast<String>(),
      codeChallengeMethodsSupported:
          (json['code_challenge_methods_supported'] as List<dynamic>?)
              ?.cast<String>(),
      scopesSupported:
          (json['scopes_supported'] as List<dynamic>?)?.cast<String>(),
      additionalMetadata: Map<String, dynamic>.from(json)
        ..remove('issuer')
        ..remove('authorization_endpoint')
        ..remove('token_endpoint')
        ..remove('registration_endpoint')
        ..remove('introspection_endpoint')
        ..remove('revocation_endpoint')
        ..remove('jwks_uri')
        ..remove('response_types_supported')
        ..remove('grant_types_supported')
        ..remove('token_endpoint_auth_methods_supported')
        ..remove('code_challenge_methods_supported')
        ..remove('scopes_supported'),
    );
  }

  Map<String, dynamic> toJson() => {
        'issuer': issuer,
        'authorization_endpoint': authorizationEndpoint,
        'token_endpoint': tokenEndpoint,
        if (registrationEndpoint != null)
          'registration_endpoint': registrationEndpoint,
        if (introspectionEndpoint != null)
          'introspection_endpoint': introspectionEndpoint,
        if (revocationEndpoint != null)
          'revocation_endpoint': revocationEndpoint,
        if (jwksUri != null) 'jwks_uri': jwksUri,
        'response_types_supported': responseTypesSupported,
        if (grantTypesSupported != null)
          'grant_types_supported': grantTypesSupported,
        if (tokenEndpointAuthMethodsSupported != null)
          'token_endpoint_auth_methods_supported':
              tokenEndpointAuthMethodsSupported,
        if (codeChallengeMethodsSupported != null)
          'code_challenge_methods_supported': codeChallengeMethodsSupported,
        if (scopesSupported != null) 'scopes_supported': scopesSupported,
        ...?additionalMetadata,
      };
}

/// Client authentication methods as defined in OAuth 2.1.
enum ClientAuthMethod {
  /// HTTP Basic authentication (RFC 6749 Section 2.3.1).
  clientSecretBasic('client_secret_basic'),

  /// Credentials in POST body (RFC 6749 Section 2.3.1).
  clientSecretPost('client_secret_post'),

  /// Public client, no authentication (RFC 6749 Section 2.1).
  none('none');

  final String value;
  const ClientAuthMethod(this.value);

  static ClientAuthMethod? fromString(String value) {
    return values.cast<ClientAuthMethod?>().firstWhere(
          (e) => e?.value == value,
          orElse: () => null,
        );
  }
}

/// Base class for OAuth errors.
class OAuthError extends Error {
  /// The error code from the OAuth spec.
  final String error;

  /// Human-readable error description.
  final String? errorDescription;

  /// URI for more information about the error.
  final String? errorUri;

  OAuthError(this.error, [this.errorDescription, this.errorUri]);

  factory OAuthError.fromJson(Map<String, dynamic> json) {
    // Handle different error formats
    String error;
    String description;

    if (json['error'] is String) {
      // Standard format: error is a string
      error = json['error'] as String;
      description = json['error_description'] as String? ?? 'unknown';
    } else if (json['error'] is Map) {
      // Nested format: error is a map with message
      final errorMap = json['error'] as Map<String, dynamic>;
      error = errorMap['type'] as String? ?? 'unknown_error';
      description = errorMap['message'] as String? ?? 'unknown';
    } else if (json['message'] != null) {
      // Alternative format: only message field exists
      error = 'unknown_error';
      description = json['message'] as String;
    } else {
      // Fallback: no recognizable error format
      error = 'unknown_error';
      description = json.toString();
    }

    final uri = json['error_uri'] as String?;

    return switch (error) {
      'invalid_client' => InvalidClientError(description, uri),
      'invalid_grant' => InvalidGrantError(description, uri),
      'unauthorized_client' => UnauthorizedClientError(description, uri),
      'invalid_request' => InvalidRequestError(description, uri),
      'invalid_scope' => InvalidScopeError(description, uri),
      'unsupported_grant_type' => UnsupportedGrantTypeError(description, uri),
      'server_error' => ServerError(description, uri),
      _ => OAuthError(error, description, uri),
    };
  }

  @override
  String toString() {
    final buffer = StringBuffer('OAuth Error: $error');
    if (errorDescription != null) {
      buffer.write(' - $errorDescription');
    }
    if (errorUri != null) {
      buffer.write(' (see: $errorUri)');
    }
    return buffer.toString();
  }
}

/// Client authentication failed.
class InvalidClientError extends OAuthError {
  InvalidClientError([String? errorDescription, String? errorUri])
      : super('invalid_client', errorDescription, errorUri);
}

/// Authorization grant is invalid, expired, or revoked.
class InvalidGrantError extends OAuthError {
  InvalidGrantError([String? errorDescription, String? errorUri])
      : super('invalid_grant', errorDescription, errorUri);
}

/// Client is not authorized to use this grant type.
class UnauthorizedClientError extends OAuthError {
  UnauthorizedClientError([String? errorDescription, String? errorUri])
      : super('unauthorized_client', errorDescription, errorUri);
}

/// Request is missing a required parameter or is malformed.
class InvalidRequestError extends OAuthError {
  InvalidRequestError([String? errorDescription, String? errorUri])
      : super('invalid_request', errorDescription, errorUri);
}

/// Requested scope is invalid, unknown, or malformed.
class InvalidScopeError extends OAuthError {
  InvalidScopeError([String? errorDescription, String? errorUri])
      : super('invalid_scope', errorDescription, errorUri);
}

/// Grant type is not supported by the authorization server.
class UnsupportedGrantTypeError extends OAuthError {
  UnsupportedGrantTypeError([String? errorDescription, String? errorUri])
      : super('unsupported_grant_type', errorDescription, errorUri);
}

/// Server encountered an error.
class ServerError extends OAuthError {
  ServerError([String? errorDescription, String? errorUri])
      : super('server_error', errorDescription, errorUri);
}

/// Error thrown when authorization is required but not provided.
class UnauthorizedError extends Error {
  final String? message;

  UnauthorizedError([this.message]);

  @override
  String toString() => 'Unauthorized${message != null ? ': $message' : ''}';
}
