import 'dart:async';

import 'package:mcp_dart/src/client/oauth_types.dart';

/// Interface for OAuth client providers.
///
/// Implementations must handle persistent storage of OAuth state including:
/// - Client registration information
/// - Access and refresh tokens
/// - PKCE code verifiers
///
/// ### Platform-Specific Redirect Handling
///
/// The [redirectToAuthorization] method must handle browser launching,
/// which is platform-specific:
///
/// **Flutter Mobile/Desktop:**
/// ```dart
/// import 'package:url_launcher/url_launcher.dart';
///
/// @override
/// Future<void> redirectToAuthorization(Uri authorizationUrl) async {
///   if (await canLaunchUrl(authorizationUrl)) {
///     await launchUrl(authorizationUrl, mode: LaunchMode.externalApplication);
///   }
/// }
/// ```
///
/// **Flutter Web:**
/// ```dart
/// import 'dart:html' as html;
///
/// @override
/// Future<void> redirectToAuthorization(Uri authorizationUrl) async {
///   html.window.location.href = authorizationUrl.toString();
/// }
/// ```
///
/// After the user completes authorization, your app must:
/// 1. Capture the authorization code from the redirect
/// 2. Call `finishAuth(authorizationCode)` on the transport
/// 3. Retry the connection
abstract class OAuthClientProvider {
  /// The redirect URI where the authorization server will send the user.
  ///
  /// This must match one of the URIs in [clientMetadata.redirectUris].
  /// For mobile apps, typically a custom URL scheme like: `myapp://oauth/callback`
  Uri get redirectUrl;

  /// Metadata describing this OAuth client for registration.
  OAuthClientMetadata get clientMetadata;

  /// Retrieves stored client information, or null if not registered yet.
  ///
  /// This is called to check if Dynamic Client Registration is needed.
  Future<OAuthClientInformation?> clientInformation();

  /// Stores client information after successful registration.
  ///
  /// Implementations should persist this data securely.
  Future<void> saveClientInformation(OAuthClientInformation info);

  /// Retrieves stored OAuth tokens, or null if not authorized yet.
  Future<OAuthTokens?> tokens();

  /// Stores OAuth tokens after successful authorization or refresh.
  ///
  /// Implementations should persist this data securely and consider
  /// encryption for sensitive tokens.
  Future<void> saveTokens(OAuthTokens tokens);

  /// Stores the PKCE code verifier before redirecting to authorization.
  ///
  /// This is needed to complete the authorization code exchange.
  Future<void> saveCodeVerifier(String verifier);

  /// Retrieves the stored PKCE code verifier.
  ///
  /// Called when exchanging the authorization code for tokens.
  Future<String> codeVerifier();

  /// Redirects the user to the authorization URL to grant permissions.
  ///
  /// Implementation is platform-specific. See class documentation for examples.
  ///
  /// This method is called when:
  /// - No tokens exist
  /// - Tokens cannot be refreshed
  /// - Authorization is required
  Future<void> redirectToAuthorization(Uri authorizationUrl);

  /// Optional: Generates a state parameter for CSRF protection.
  ///
  /// Override this getter to provide custom state generation.
  /// If null, no state parameter will be included.
  /// Recommended to return a cryptographically random string.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Future<String> Function()? get state => () async {
  ///   final random = Random.secure();
  ///   final bytes = List<int>.generate(32, (_) => random.nextInt(256));
  ///   return base64UrlEncode(bytes);
  /// };
  /// ```
  Future<String> Function()? get state => null;

  /// Optional: Adds custom client authentication to token requests.
  ///
  /// Override this getter to provide custom authentication for non-standard methods.
  /// If null, standard OAuth 2.1 methods are used automatically.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Future<void> Function(
  ///   Map<String, String> headers,
  ///   Map<String, String> params,
  ///   Uri url,
  ///   AuthorizationServerMetadata? metadata,
  /// )? get addClientAuthentication => (headers, params, url, metadata) async {
  ///   // Custom authentication logic
  ///   headers['X-Custom-Auth'] = 'my-token';
  /// };
  /// ```
  Future<void> Function(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  )? get addClientAuthentication => null;

  /// Optional: Custom validation for RFC 8707 Resource Indicators.
  ///
  /// Override this getter to provide custom resource URL validation.
  /// If null, default validation ensures the resource matches the MCP server URL.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Future<Uri?> Function(Uri serverUrl, String? resource)? get validateResourceUrl =>
  ///   (serverUrl, resource) async {
  ///     // Custom validation logic
  ///     return resource != null ? Uri.parse(resource) : null;
  ///   };
  /// ```
  Future<Uri?> Function(Uri serverUrl, String? resource)?
      get validateResourceUrl => null;

  /// Optional: Invalidates stored credentials when they become invalid.
  ///
  /// Override this getter to handle credential invalidation.
  /// Called automatically when the server indicates credentials are no longer valid:
  /// - 'all': Clear everything (client info, tokens, verifier)
  /// - 'client': Clear client registration only
  /// - 'tokens': Clear tokens only
  /// - 'verifier': Clear code verifier only
  ///
  /// If null, credentials will not be automatically cleared.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Future<void> Function(String scope)? get invalidateCredentials =>
  ///   (scope) async {
  ///     switch (scope) {
  ///       case 'all':
  ///         // Clear all stored credentials
  ///         break;
  ///       // ...
  ///     }
  ///   };
  /// ```
  Future<void> Function(String scope)? get invalidateCredentials => null;
}
