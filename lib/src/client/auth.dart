/// OAuth 2.1 authorization implementation for MCP clients.
///
/// This library provides functions to orchestrate the OAuth 2.1 authorization
/// flow for MCP servers, including:
/// - Metadata discovery (RFC 9728, RFC 8414, OIDC Discovery)
/// - Dynamic Client Registration (RFC 7591)
/// - Authorization code flow with PKCE
/// - Token exchange and refresh
/// - Resource indicator validation (RFC 8707)
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io' show SocketException;
import 'package:http/http.dart' as http;
import 'package:mcp_dart/src/client/oauth_provider.dart';
import 'package:mcp_dart/src/client/oauth_types.dart';
import 'package:pkce/pkce.dart';

/// Result of an auth() attempt.
enum AuthResult {
  /// Successfully authorized with access token.
  authorized('AUTHORIZED'),

  /// Needs to redirect user to authorization URL.
  redirect('REDIRECT');

  final String value;
  const AuthResult(this.value);
}

/// Extracts the resource_metadata URL from a 401 response's WWW-Authenticate header.
///
/// Returns null if the header is missing or malformed.
///
/// Example header:
/// ```
/// WWW-Authenticate: Bearer realm="mcp",
///   resource_metadata="https://server.com/.well-known/oauth-protected-resource"
/// ```
Uri? extractResourceMetadataUrl(http.StreamedResponse response) {
  final authenticateHeader = response.headers['www-authenticate'];
  if (authenticateHeader == null) return null;

  final parts = authenticateHeader.split(' ');
  if (parts.length < 2 || parts[0].toLowerCase() != 'bearer') {
    return null;
  }

  final regex = RegExp(r'resource_metadata="([^"]*)"');
  final match = regex.firstMatch(authenticateHeader);
  if (match == null) return null;

  try {
    return Uri.parse(match.group(1)!);
  } catch (_) {
    return null;
  }
}

/// Discovers OAuth 2.0 Protected Resource Metadata (RFC 9728).
///
/// Attempts to fetch metadata from the well-known endpoint at the server URL.
/// Returns null if the server returns 404 (no auth required).
/// Throws on other HTTP errors.
///
/// - [serverUrl]: The MCP server URL
/// - [resourceMetadataUrl]: Optional explicit metadata URL from 401 response
Future<OAuthProtectedResourceMetadata?> discoverOAuthProtectedResourceMetadata(
  Uri serverUrl, {
  Uri? resourceMetadataUrl,
}) async {
  final client = http.Client();
  try {
    Uri metadataUrl;
    if (resourceMetadataUrl != null) {
      metadataUrl = resourceMetadataUrl;
    } else {
      // Build RFC 9728 well-known URL
      final path = serverUrl.path.endsWith('/')
          ? serverUrl.path.substring(0, serverUrl.path.length - 1)
          : serverUrl.path;
      metadataUrl = serverUrl.replace(
        path: '/.well-known/oauth-protected-resource$path',
      );
    }

    final response = await client.get(
      metadataUrl,
      headers: {'accept': 'application/json'},
    );

    if (response.statusCode == 404) {
      return null; // No auth required
    }

    if (response.statusCode != 200) {
      throw OAuthError(
        'metadata_fetch_failed',
        'HTTP ${response.statusCode} fetching protected resource metadata',
      );
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return OAuthProtectedResourceMetadata.fromJson(json);
  } finally {
    client.close();
  }
}

/// Builds a list of discovery URLs to try for authorization server metadata.
///
/// Returns URLs in priority order:
/// 1. OAuth metadata at the given URL
/// 2. OAuth metadata at root (if URL has path)
/// 3. OIDC discovery endpoints
List<({Uri url, String type})> buildDiscoveryUrls(Uri authServerUrl) {
  final urls = <({Uri url, String type})>[];
  final hasPath = authServerUrl.path != '/' && authServerUrl.path.isNotEmpty;
  final pathname = authServerUrl.path.endsWith('/')
      ? authServerUrl.path.substring(0, authServerUrl.path.length - 1)
      : authServerUrl.path;

  if (hasPath) {
    // Path-specific OAuth metadata
    urls.add((
      url: authServerUrl.replace(
        path: '/.well-known/oauth-authorization-server$pathname',
      ),
      type: 'oauth'
    ));
  }

  // Root OAuth metadata
  urls.add((
    url: authServerUrl.replace(path: '/.well-known/oauth-authorization-server'),
    type: 'oauth'
  ));

  if (hasPath) {
    // RFC 8414 style OIDC
    urls.add((
      url: authServerUrl.replace(
        path: '/.well-known/openid-configuration$pathname',
      ),
      type: 'oidc'
    ));

    // OIDC Discovery 1.0 style
    urls.add((
      url: authServerUrl.replace(
        path: '$pathname/.well-known/openid-configuration',
      ),
      type: 'oidc'
    ));
  } else {
    // Root OIDC
    urls.add((
      url: authServerUrl.replace(path: '/.well-known/openid-configuration'),
      type: 'oidc'
    ));
  }

  return urls;
}

/// Discovers authorization server metadata with OAuth 2.0 and OIDC fallback.
///
/// Implements RFC 8414 (OAuth) and OIDC Discovery 1.0 specifications.
/// Tries multiple well-known endpoints in priority order.
///
/// Returns null if no metadata is found at any endpoint.
Future<AuthorizationServerMetadata?> discoverAuthorizationServerMetadata(
  Uri authServerUrl,
) async {
  final client = http.Client();
  try {
    final urlsToTry = buildDiscoveryUrls(authServerUrl);

    for (final entry in urlsToTry) {
      try {
        final response = await client.get(
          entry.url,
          headers: {'accept': 'application/json'},
        );

        if (response.statusCode >= 400 && response.statusCode < 500) {
          continue; // Try next URL
        }

        if (response.statusCode != 200) {
          throw OAuthError(
            'metadata_fetch_failed',
            'HTTP ${response.statusCode} fetching ${entry.type} metadata from ${entry.url}',
          );
        }

        final json = jsonDecode(response.body) as Map<String, dynamic>;
        return AuthorizationServerMetadata.fromJson(json);
      } on SocketException {
        // Network error, try next URL
        continue;
      }
    }

    return null; // No metadata found
  } finally {
    client.close();
  }
}

/// Selects the resource URL for RFC 8707 Resource Indicators.
///
/// Returns null if no protected resource metadata exists (resource parameter should be omitted).
/// Uses custom validation if provided, otherwise validates that metadata resource matches server.
Future<Uri?> selectResourceUrl(
  Uri serverUrl,
  OAuthClientProvider provider,
  OAuthProtectedResourceMetadata? resourceMetadata,
) async {
  final defaultResource = _resourceUrlFromServerUrl(serverUrl);

  // Try custom validation if implemented
  final customValidator = provider.validateResourceUrl;
  final customResult = customValidator != null
      ? await customValidator(defaultResource, resourceMetadata?.resource)
      : null;

  // If custom validation was implemented and returned a result, use it
  if (customResult != null) {
    return customResult;
  }

  // No metadata = no resource parameter
  if (resourceMetadata == null) {
    return null;
  }

  // Validate metadata resource matches server
  final metadataResourceUri = Uri.parse(resourceMetadata.resource);
  if (!_checkResourceAllowed(defaultResource, metadataResourceUri)) {
    throw OAuthError(
      'resource_mismatch',
      'Protected resource ${resourceMetadata.resource} does not match expected $defaultResource (or origin)',
    );
  }

  // Prefer metadata resource
  return metadataResourceUri;
}

/// Derives the resource URL from a server URL (strips query and fragment).
Uri _resourceUrlFromServerUrl(Uri serverUrl) {
  return serverUrl.replace(query: '', fragment: '');
}

/// Checks if a requested resource is compatible with configured resource.
///
/// Allows exact match or origin match (scheme + host + port).
bool _checkResourceAllowed(Uri requested, Uri configured) {
  // Exact match
  if (requested.toString() == configured.toString()) {
    return true;
  }

  // Origin match (scheme + host + port)
  return requested.scheme == configured.scheme &&
      requested.host == configured.host &&
      requested.port == configured.port;
}

/// Determines the best client authentication method based on server support.
///
/// Priority order (highest to lowest):
/// 1. client_secret_basic (if client secret available)
/// 2. client_secret_post (if client secret available)
/// 3. none (for public clients)
ClientAuthMethod selectClientAuthMethod(
  OAuthClientInformation clientInfo,
  List<String> supportedMethods,
) {
  final hasClientSecret = clientInfo.clientSecret != null;

  // If server doesn't specify supported methods, use RFC 6749 defaults
  if (supportedMethods.isEmpty) {
    return hasClientSecret
        ? ClientAuthMethod.clientSecretPost
        : ClientAuthMethod.none;
  }

  // Prefer server-returned method if valid
  if (clientInfo is OAuthClientInformationPartial &&
      clientInfo.tokenEndpointAuthMethod != null) {
    final method = ClientAuthMethod.fromString(
      clientInfo.tokenEndpointAuthMethod!,
    );
    if (method != null && supportedMethods.contains(method.value)) {
      return method;
    }
  }
  if (clientInfo is OAuthClientInformationFull &&
      clientInfo.tokenEndpointAuthMethod != null) {
    final method = ClientAuthMethod.fromString(
      clientInfo.tokenEndpointAuthMethod!,
    );
    if (method != null && supportedMethods.contains(method.value)) {
      return method;
    }
  }

  // Try methods in priority order
  if (hasClientSecret &&
      supportedMethods.contains(ClientAuthMethod.clientSecretBasic.value)) {
    return ClientAuthMethod.clientSecretBasic;
  }

  if (hasClientSecret &&
      supportedMethods.contains(ClientAuthMethod.clientSecretPost.value)) {
    return ClientAuthMethod.clientSecretPost;
  }

  if (supportedMethods.contains(ClientAuthMethod.none.value)) {
    return ClientAuthMethod.none;
  }

  // Fallback
  return hasClientSecret
      ? ClientAuthMethod.clientSecretPost
      : ClientAuthMethod.none;
}

/// Applies client authentication to HTTP request based on the specified method.
void applyClientAuthentication(
  ClientAuthMethod method,
  OAuthClientInformation clientInfo,
  Map<String, String> headers,
  Map<String, String> params,
) {
  switch (method) {
    case ClientAuthMethod.clientSecretBasic:
      _applyBasicAuth(clientInfo.clientId, clientInfo.clientSecret, headers);
      break;
    case ClientAuthMethod.clientSecretPost:
      _applyPostAuth(clientInfo.clientId, clientInfo.clientSecret, params);
      break;
    case ClientAuthMethod.none:
      _applyPublicAuth(clientInfo.clientId, params);
      break;
  }
}

/// Applies HTTP Basic authentication (RFC 6749 Section 2.3.1).
void _applyBasicAuth(
  String clientId,
  String? clientSecret,
  Map<String, String> headers,
) {
  if (clientSecret == null) {
    throw OAuthError(
      'invalid_client',
      'client_secret_basic authentication requires a client_secret',
    );
  }

  final credentials = base64Encode(utf8.encode('$clientId:$clientSecret'));
  headers['authorization'] = 'Basic $credentials';
}

/// Applies POST body authentication (RFC 6749 Section 2.3.1).
void _applyPostAuth(
  String clientId,
  String? clientSecret,
  Map<String, String> params,
) {
  params['client_id'] = clientId;
  if (clientSecret != null) {
    params['client_secret'] = clientSecret;
  }
}

/// Applies public client authentication (RFC 6749 Section 2.1).
void _applyPublicAuth(String clientId, Map<String, String> params) {
  params['client_id'] = clientId;
}

/// Parses an OAuth error response from HTTP response.
///
/// Returns a specific [OAuthError] subclass based on the error code,
/// or a generic [ServerError] if parsing fails.
OAuthError parseErrorResponse(http.Response response) {
  final statusCode = response.statusCode;
  final body = response.body;

  try {
    final json = jsonDecode(body) as Map<String, dynamic>;
    return OAuthError.fromJson(json);
  } catch (e) {
    // Not a valid OAuth error response
    return ServerError(
      'HTTP $statusCode: Invalid OAuth error response: $e. Raw body: $body',
    );
  }
}

/// Begins the authorization flow by generating PKCE and constructing the authorization URL.
///
/// Returns the authorization URL and code verifier for later token exchange.
Future<({Uri authorizationUrl, String codeVerifier})> startAuthorization(
  Uri authServerUrl, {
  required AuthorizationServerMetadata? metadata,
  required OAuthClientInformation clientInfo,
  required Uri redirectUrl,
  String? scope,
  String? state,
  Uri? resource,
}) async {
  Uri authorizationUrl;

  if (metadata != null) {
    authorizationUrl = Uri.parse(metadata.authorizationEndpoint);

    // Validate server supports authorization code flow
    if (!metadata.responseTypesSupported.contains('code')) {
      throw OAuthError(
        'unsupported_response_type',
        'Authorization server does not support response type "code"',
      );
    }

    // Validate server supports PKCE S256
    if (metadata.codeChallengeMethodsSupported != null &&
        !metadata.codeChallengeMethodsSupported!.contains('S256')) {
      throw OAuthError(
        'unsupported_code_challenge_method',
        'Authorization server does not support code challenge method S256',
      );
    }
  } else {
    // Fallback if no metadata
    authorizationUrl = authServerUrl.replace(path: '/authorize');
  }

  // Generate PKCE challenge
  final pkcePair = PkcePair.generate();
  final codeVerifier = pkcePair.codeVerifier;
  final codeChallenge = pkcePair.codeChallenge;

  // Build authorization URL with parameters
  final params = <String, String>{
    'response_type': 'code',
    'client_id': clientInfo.clientId,
    'code_challenge': codeChallenge,
    'code_challenge_method': 'S256',
    'redirect_uri': redirectUrl.toString(),
  };

  if (state != null) {
    params['state'] = state;
  }

  if (scope != null) {
    params['scope'] = scope;

    // OIDC offline_access requires consent prompt
    if (scope.contains('offline_access')) {
      params['prompt'] = 'consent';
    }
  }

  if (resource != null) {
    params['resource'] = resource.toString();
  }

  final finalAuthUrl = authorizationUrl.replace(queryParameters: params);

  return (authorizationUrl: finalAuthUrl, codeVerifier: codeVerifier);
}

/// Exchanges an authorization code for tokens.
///
/// Supports multiple client authentication methods based on server support.
Future<OAuthTokens> exchangeAuthorization(
  Uri authServerUrl, {
  required AuthorizationServerMetadata? metadata,
  required OAuthClientInformation clientInfo,
  required String authorizationCode,
  required String codeVerifier,
  required Uri redirectUri,
  Uri? resource,
  Future<void> Function(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  )? addClientAuthentication,
}) async {
  const grantType = 'authorization_code';

  final tokenUrl = metadata != null
      ? Uri.parse(metadata.tokenEndpoint)
      : authServerUrl.replace(path: '/token');

  // Validate grant type support
  if (metadata?.grantTypesSupported != null &&
      !metadata!.grantTypesSupported!.contains(grantType)) {
    throw OAuthError(
      'unsupported_grant_type',
      'Authorization server does not support grant type $grantType',
    );
  }

  final client = http.Client();
  try {
    final headers = <String, String>{
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
    };

    final params = <String, String>{
      'grant_type': grantType,
      'code': authorizationCode,
      'code_verifier': codeVerifier,
      'redirect_uri': redirectUri.toString(),
    };

    // Apply client authentication
    if (addClientAuthentication != null) {
      await addClientAuthentication(headers, params, tokenUrl, metadata);
    } else {
      final supportedMethods =
          metadata?.tokenEndpointAuthMethodsSupported ?? [];
      final authMethod = selectClientAuthMethod(clientInfo, supportedMethods);
      applyClientAuthentication(authMethod, clientInfo, headers, params);
    }

    if (resource != null) {
      params['resource'] = resource.toString();
    }

    // Make request
    final response = await client.post(
      tokenUrl,
      headers: headers,
      body: params,
    );

    if (response.statusCode != 200) {
      throw parseErrorResponse(response);
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return OAuthTokens.fromJson(json);
  } finally {
    client.close();
  }
}

/// Refreshes an access token using a refresh token.
///
/// Preserves the original refresh token if a new one is not returned.
Future<OAuthTokens> refreshAuthorization(
  Uri authServerUrl, {
  required AuthorizationServerMetadata? metadata,
  required OAuthClientInformation clientInfo,
  required String refreshToken,
  Uri? resource,
  Future<void> Function(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  )? addClientAuthentication,
}) async {
  const grantType = 'refresh_token';

  final tokenUrl = metadata != null
      ? Uri.parse(metadata.tokenEndpoint)
      : authServerUrl.replace(path: '/token');

  // Validate grant type support
  if (metadata?.grantTypesSupported != null &&
      !metadata!.grantTypesSupported!.contains(grantType)) {
    throw OAuthError(
      'unsupported_grant_type',
      'Authorization server does not support grant type $grantType',
    );
  }

  final client = http.Client();
  try {
    final headers = <String, String>{
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
    };

    final params = <String, String>{
      'grant_type': grantType,
      'refresh_token': refreshToken,
    };

    // Apply client authentication
    if (addClientAuthentication != null) {
      await addClientAuthentication(headers, params, tokenUrl, metadata);
    } else {
      final supportedMethods =
          metadata?.tokenEndpointAuthMethodsSupported ?? [];
      final authMethod = selectClientAuthMethod(clientInfo, supportedMethods);
      applyClientAuthentication(authMethod, clientInfo, headers, params);
    }

    if (resource != null) {
      params['resource'] = resource.toString();
    }

    // Make request
    final response = await client.post(
      tokenUrl,
      headers: headers,
      body: params,
    );

    if (response.statusCode != 200) {
      throw parseErrorResponse(response);
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;

    // Preserve original refresh token if not replaced
    final tokens = OAuthTokens.fromJson(json);
    if (tokens.refreshToken == null) {
      return OAuthTokens(
        accessToken: tokens.accessToken,
        refreshToken: refreshToken,
        tokenType: tokens.tokenType,
        expiresIn: tokens.expiresIn,
        scope: tokens.scope,
      );
    }

    return tokens;
  } finally {
    client.close();
  }
}

/// Performs OAuth 2.0 Dynamic Client Registration (RFC 7591).
Future<OAuthClientInformationFull> registerClient(
  Uri authServerUrl, {
  required AuthorizationServerMetadata? metadata,
  required OAuthClientMetadata clientMetadata,
}) async {
  Uri registrationUrl;

  if (metadata != null) {
    if (metadata.registrationEndpoint == null) {
      throw OAuthError(
        'unsupported_operation',
        'Authorization server does not support dynamic client registration',
      );
    }
    registrationUrl = Uri.parse(metadata.registrationEndpoint!);
  } else {
    registrationUrl = authServerUrl.replace(path: '/register');
  }

  final client = http.Client();
  try {
    final response = await client.post(
      registrationUrl,
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json',
      },
      body: jsonEncode(clientMetadata.toJson()),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      throw parseErrorResponse(response);
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return OAuthClientInformationFull.fromJson(json);
  } finally {
    client.close();
  }
}

/// Checks if tokens need refreshing.
///
/// Returns true if tokens are expired or will expire soon (within 60 seconds).
///
/// Example:
/// ```dart
/// if (await shouldRefreshTokens(provider)) {
///   print('Tokens need refresh');
/// }
/// ```
Future<bool> shouldRefreshTokens(OAuthClientProvider provider) async {
  final currentTokens = await provider.tokens();
  if (currentTokens == null) return false;
  if (currentTokens.refreshToken == null) return false;
  return currentTokens.isExpired || currentTokens.willExpireSoon();
}

/// Proactively refreshes tokens if they are expired or will expire soon.
///
/// Returns true if tokens were successfully refreshed, false if no refresh was needed.
/// Throws [OAuthError] if refresh fails.
///
/// This function checks if the access token is expired or will expire within 60 seconds,
/// and if so, uses the refresh token to obtain new tokens.
///
/// The [StreamableHttpClientTransport] automatically calls this before making requests.
///
/// Example:
/// ```dart
/// try {
///   final refreshed = await refreshTokensIfNeeded(
///     provider,
///     serverUrl: serverUrl,
///   );
///   if (refreshed) {
///     print('Tokens refreshed successfully');
///   }
/// } on OAuthError catch (e) {
///   print('Failed to refresh tokens: ${e.error}');
/// }
/// ```
Future<bool> refreshTokensIfNeeded(
  OAuthClientProvider provider,
  Uri serverUrl, {
  Uri? resourceMetadataUrl,
}) async {
  if (!await shouldRefreshTokens(provider)) {
    return false; // Token is still valid or can't be refreshed
  }

  // Perform the refresh by calling auth() without an authorization code
  // The auth() function will automatically use the refresh token flow
  final result = await auth(
    provider,
    serverUrl: serverUrl,
    resourceMetadataUrl: resourceMetadataUrl,
  );

  return result == AuthResult.authorized;
}

/// Orchestrates the complete OAuth 2.1 authorization flow.
///
/// This is the main entry point for authorization. It handles:
/// - Metadata discovery
/// - Client registration (if needed)
/// - Authorization code exchange
/// - Token refresh
/// - Error recovery with credential invalidation
///
/// Returns [AuthResult.authorized] if tokens were obtained,
/// or [AuthResult.redirect] if user needs to authorize in browser.
///
/// Throws [UnauthorizedError] if auth provider is missing or authorization fails.
Future<AuthResult> auth(
  OAuthClientProvider provider, {
  required Uri serverUrl,
  String? authorizationCode,
  String? scope,
  Uri? resourceMetadataUrl,
}) async {
  try {
    return await _authInternal(
      provider,
      serverUrl: serverUrl,
      authorizationCode: authorizationCode,
      scope: scope,
      resourceMetadataUrl: resourceMetadataUrl,
    );
  } catch (error) {
    // Handle recoverable errors by invalidating credentials and retrying
    if (error is InvalidClientError || error is UnauthorizedClientError) {
      final invalidator = provider.invalidateCredentials;
      if (invalidator != null) {
        await invalidator('all');
      }
      return await _authInternal(
        provider,
        serverUrl: serverUrl,
        authorizationCode: authorizationCode,
        scope: scope,
        resourceMetadataUrl: resourceMetadataUrl,
      );
    } else if (error is InvalidGrantError) {
      final invalidator = provider.invalidateCredentials;
      if (invalidator != null) {
        await invalidator('tokens');
      }
      return await _authInternal(
        provider,
        serverUrl: serverUrl,
        authorizationCode: authorizationCode,
        scope: scope,
        resourceMetadataUrl: resourceMetadataUrl,
      );
    }

    rethrow;
  }
}

/// Internal auth implementation without error recovery.
Future<AuthResult> _authInternal(
  OAuthClientProvider provider, {
  required Uri serverUrl,
  String? authorizationCode,
  String? scope,
  Uri? resourceMetadataUrl,
}) async {
  // Step 1: Discover protected resource metadata
  OAuthProtectedResourceMetadata? resourceMetadata;
  Uri? authorizationServerUrl;

  try {
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(
      serverUrl,
      resourceMetadataUrl: resourceMetadataUrl,
    );
    if (resourceMetadata?.authorizationServers != null &&
        resourceMetadata!.authorizationServers!.isNotEmpty) {
      authorizationServerUrl =
          Uri.parse(resourceMetadata.authorizationServers!.first);
    }
  } catch (_) {
    // Ignore errors, fall back to server URL as auth server
  }

  authorizationServerUrl ??= serverUrl;

  // Step 2: Select resource URL
  final resource = await selectResourceUrl(
    serverUrl,
    provider,
    resourceMetadata,
  );

  // Step 3: Discover authorization server metadata
  final metadata =
      await discoverAuthorizationServerMetadata(authorizationServerUrl);

  // Step 4: Handle client registration
  var clientInfo = await provider.clientInformation();
  if (clientInfo == null) {
    if (authorizationCode != null) {
      throw OAuthError(
        'invalid_request',
        'Existing OAuth client information is required when exchanging an authorization code',
      );
    }

    final fullInfo = await registerClient(
      authorizationServerUrl,
      metadata: metadata,
      clientMetadata: provider.clientMetadata,
    );

    await provider.saveClientInformation(fullInfo);
    clientInfo = fullInfo;
  }

  // Step 5: Exchange authorization code if provided
  if (authorizationCode != null) {
    final codeVerifier = await provider.codeVerifier();
    final tokens = await exchangeAuthorization(
      authorizationServerUrl,
      metadata: metadata,
      clientInfo: clientInfo,
      authorizationCode: authorizationCode,
      codeVerifier: codeVerifier,
      redirectUri: provider.redirectUrl,
      resource: resource,
      addClientAuthentication: provider.addClientAuthentication,
    );

    await provider.saveTokens(tokens);
    return AuthResult.authorized;
  }

  // Step 6: Try to refresh existing tokens
  final tokens = await provider.tokens();
  if (tokens?.refreshToken != null) {
    try {
      final newTokens = await refreshAuthorization(
        authorizationServerUrl,
        metadata: metadata,
        clientInfo: clientInfo,
        refreshToken: tokens!.refreshToken!,
        resource: resource,
        addClientAuthentication: provider.addClientAuthentication,
      );

      await provider.saveTokens(newTokens);
      return AuthResult.authorized;
    } on OAuthError catch (error) {
      // If this is a ServerError or unknown type, try to continue with new authorization
      if (error is! ServerError) {
        rethrow;
      }
      // Otherwise fall through to start new authorization
    }
  }

  // Step 7: Start new authorization flow
  final stateGenerator = provider.state;
  final state = stateGenerator != null ? await stateGenerator() : null;
  final authResult = await startAuthorization(
    authorizationServerUrl,
    metadata: metadata,
    clientInfo: clientInfo,
    redirectUrl: provider.redirectUrl,
    scope: scope ?? provider.clientMetadata.scope,
    state: state,
    resource: resource,
  );

  await provider.saveCodeVerifier(authResult.codeVerifier);
  await provider.redirectToAuthorization(authResult.authorizationUrl);

  return AuthResult.redirect;
}
