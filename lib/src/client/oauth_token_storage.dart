import 'package:mcp_dart/src/client/oauth_types.dart';

/// Abstract interface for OAuth tokens storage.
///
/// Implementations should provide secure persistent storage for OAuth tokens,
/// client information, and code verifiers across app restarts.
abstract class TokensStorage {
  /// Load all persisted OAuth data from storage.
  Future<void> loadPersistedData();

  /// Get stored tokens.
  Future<OAuthTokens?> getTokens();

  /// Save tokens to storage.
  Future<void> saveTokens(OAuthTokens tokens);

  /// Get stored client information.
  Future<OAuthClientInformation?> getClientInformation();

  /// Save client information to storage.
  Future<void> saveClientInformation(OAuthClientInformation info);

  /// Get stored code verifier.
  Future<String> getCodeVerifier();

  /// Save code verifier to storage.
  Future<void> saveCodeVerifier(String verifier);

  /// Invalidate credentials based on scope.
  ///
  /// Supported scopes:
  /// - 'all': Clear all stored data
  /// - 'tokens': Clear only tokens
  /// - 'client': Clear only client information
  /// - 'verifier': Clear only code verifier
  Future<void> invalidate(String scope);

  /// Clear all stored OAuth data.
  Future<void> clearAll();
}
