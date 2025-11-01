# OAuth 2.1 Authentication Usage Guide

This guide demonstrates how to use OAuth 2.1 authentication with MCP Dart SDK for connecting to authenticated Streamable HTTP MCP servers.

## Overview

The MCP Dart SDK implements OAuth 2.1 with PKCE (Proof Key for Code Exchange) to securely authenticate clients with remote MCP servers. The implementation follows these RFCs:

- **RFC 9728**: OAuth 2.0 Protected Resource Metadata
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata Discovery
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration
- **RFC 8707**: Resource Indicators for OAuth 2.0
- **OIDC Discovery**: OpenID Connect Discovery 1.0

## Basic Usage

### 1. Implement OAuthClientProvider

The `OAuthClientProvider` interface handles OAuth state management. You must implement this interface to provide persistent storage for:
- Client registration information
- Access and refresh tokens
- PKCE code verifiers

```dart
import 'package:mcp_dart/mcp_dart.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

class MyOAuthProvider implements OAuthClientProvider {
  final SharedPreferences _prefs;
  
  MyOAuthProvider(this._prefs);
  
  @override
  Uri get redirectUrl => Uri.parse('myapp://oauth/callback');
  
  @override
  OAuthClientMetadata get clientMetadata => OAuthClientMetadata(
    clientName: 'My MCP Client',
    redirectUris: [redirectUrl.toString()],
    scope: 'mcp:tools mcp:resources',
  );
  
  // Token storage
  @override
  Future<OAuthTokens?> tokens() async {
    final json = _prefs.getString('oauth_tokens');
    if (json == null) return null;
    return OAuthTokens.fromJson(jsonDecode(json));
  }
  
  @override
  Future<void> saveTokens(OAuthTokens tokens) async {
    await _prefs.setString('oauth_tokens', jsonEncode(tokens.toJson()));
  }
  
  // Client registration storage
  @override
  Future<OAuthClientInformation?> clientInformation() async {
    final json = _prefs.getString('oauth_client');
    if (json == null) return null;
    return OAuthClientInformation.fromJson(jsonDecode(json));
  }
  
  @override
  Future<void> saveClientInformation(OAuthClientInformation info) async {
    await _prefs.setString('oauth_client', jsonEncode(info.toJson()));
  }
  
  // PKCE code verifier storage
  @override
  Future<void> saveCodeVerifier(String verifier) async {
    await _prefs.setString('oauth_verifier', verifier);
  }
  
  @override
  Future<String> codeVerifier() async {
    return _prefs.getString('oauth_verifier') ?? '';
  }
  
  // Redirect to authorization (platform-specific)
  @override
  Future<void> redirectToAuthorization(Uri authorizationUrl) async {
    if (await canLaunchUrl(authorizationUrl)) {
      await launchUrl(authorizationUrl, mode: LaunchMode.externalApplication);
    } else {
      throw Exception('Could not launch $authorizationUrl');
    }
  }
  
  // Optional: CSRF protection
  @override
  Future<String> state() async {
    // Generate cryptographically random state parameter
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64UrlEncode(bytes);
  }
  
  // Optional: Credential invalidation
  @override
  Future<void> invalidateCredentials(String scope) async {
    switch (scope) {
      case 'all':
        await _prefs.remove('oauth_tokens');
        await _prefs.remove('oauth_client');
        await _prefs.remove('oauth_verifier');
        break;
      case 'tokens':
        await _prefs.remove('oauth_tokens');
        break;
      case 'client':
        await _prefs.remove('oauth_client');
        break;
      case 'verifier':
        await _prefs.remove('oauth_verifier');
        break;
    }
  }
}
```

### 2. Create Authenticated Transport

```dart
Future<void> connectToMcpServer() async {
  final prefs = await SharedPreferences.getInstance();
  final authProvider = MyOAuthProvider(prefs);
  
  // Create transport with auth
  final transport = StreamableHttpClientTransport(
    Uri.parse('https://my-mcp-server.com/mcp'),
    opts: StreamableHttpClientTransportOptions(
      authProvider: authProvider,
    ),
  );
  
  // Create and connect client
  final client = Client(
    Implementation(name: 'my-client', version: '1.0.0'),
  );
  
  try {
    await client.connect(transport);
    print('Connected!');
  } on UnauthorizedError catch (e) {
    // User needs to authorize in browser
    // The redirectToAuthorization method was already called
    print('Authorization required: ${e.message}');
  }
}
```

### 3. Handle Authorization Callback

After the user completes authorization in their browser, your app will receive a redirect with an authorization code. You need to capture this and complete the flow:

```dart
// In your deep link handler (e.g., using go_router or uni_links)
Future<void> handleOAuthCallback(Uri callbackUri) async {
  final code = callbackUri.queryParameters['code'];
  if (code == null) {
    print('No authorization code received');
    return;
  }
  
  // Complete auth flow
  await transport.finishAuth(code);
  
  // Retry connection
  await client.connect(transport);
}
```

## Advanced Usage

### Custom Client Authentication

Override `addClientAuthentication` to implement custom authentication methods:

```dart
class CustomAuthProvider extends MyOAuthProvider {
  @override
  Future<void> addClientAuthentication(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  ) async {
    // Example: JWT bearer token authentication
    final jwt = await generateClientJwt();
    params['client_assertion_type'] = 
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    params['client_assertion'] = jwt;
  }
}
```

### Custom Resource Validation

Override `validateResourceUrl` for custom RFC 8707 resource validation:

```dart
class CustomAuthProvider extends MyOAuthProvider {
  @override
  Future<Uri?> validateResourceUrl(Uri serverUrl, String? resource) async {
    if (resource == null) return null;
    
    final resourceUri = Uri.parse(resource);
    
    // Custom validation logic
    if (!_isValidResource(resourceUri)) {
      throw OAuthError('invalid_resource', 'Resource not allowed');
    }
    
    return resourceUri;
  }
}
```

## Platform-Specific Considerations

### Flutter Mobile (iOS/Android)

Use `url_launcher` package for browser redirection:

```yaml
dependencies:
  url_launcher: ^6.2.0
```

Register your custom URL scheme in platform configurations:

**iOS (Info.plist):**
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>myapp</string>
    </array>
  </dict>
</array>
```

**Android (AndroidManifest.xml):**
```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="myapp" android:host="oauth" />
</intent-filter>
```

## Error Handling

The SDK provides specific error types for OAuth failures:

```dart
try {
  await client.connect(transport);
} on UnauthorizedError catch (e) {
  // No valid credentials, user needs to authorize
  print('Authorization required: ${e.message}');
} on InvalidClientError catch (e) {
  // Client credentials are invalid
  print('Client error: ${e.errorDescription}');
} on InvalidGrantError catch (e) {
  // Token or code is invalid/expired
  print('Grant error: ${e.errorDescription}');
} on OAuthError catch (e) {
  // Other OAuth errors
  print('OAuth error: ${e.error} - ${e.errorDescription}');
}
```

## Security Best Practices

1. **Store tokens securely**: Use `flutter_secure_storage` instead of `shared_preferences` for sensitive data
2. **Validate state parameter**: Always generate and validate the state parameter to prevent CSRF attacks
3. **Use PKCE**: The SDK automatically uses PKCE (S256) for all authorization flows
4. **Handle token expiry**: The SDK automatically refreshes tokens when possible
5. **Clear credentials**: Implement `invalidateCredentials` to handle logout properly

## Testing

For testing without a real OAuth server, you can create a mock provider:

```dart
class MockAuthProvider implements OAuthClientProvider {
  @override
  Future<OAuthTokens?> tokens() async {
    return OAuthTokens(
      accessToken: 'mock_access_token',
      refreshToken: 'mock_refresh_token',
    );
  }
  
  // ... implement other methods
}
```

## Troubleshooting

### "Server returned 401 after successful authentication"

This indicates an infinite authentication loop. The SDK has circuit breaker protection, but ensure:
- Your tokens are being saved correctly
- The server is accepting your access token
- Token is not being invalidated between requests

### "No authorization code received"

Check that:
- Your redirect URI matches exactly in client metadata
- Deep link handling is properly configured for your platform
- The authorization server is redirecting to the correct URI

### "Authorization server does not support X"

The SDK validates server capabilities during discovery. If you see this error:
- Check that the server implements the required OAuth 2.1 features
- Verify the server's `.well-known` metadata endpoints are accessible
- Ensure PKCE with S256 is supported

## Additional Resources

- [MCP Authorization Specification](https://spec.modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7636: PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [Understanding Authorization in MCP](https://modelcontextprotocol.io/docs/concepts/authorization)
