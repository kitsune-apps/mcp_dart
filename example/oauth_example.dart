/// Example demonstrating OAuth 2.1 authentication with MCP Dart SDK.
///
/// This example shows how to:
/// - Implement OAuthClientProvider for token storage
/// - Connect to an authenticated MCP server
/// - Handle authorization callbacks automatically
/// - Launch browser and receive callback via local HTTP server
/// - Implement secure token storage
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:mcp_dart/mcp_dart.dart';

/// Simple in-memory OAuth provider for demonstration.
///
/// ⚠️ WARNING: This stores tokens in memory only. In production:
/// - Use flutter_secure_storage for sensitive data
/// - Implement proper persistence across app restarts
/// - Handle token expiry and refresh logic
class InMemoryOAuthProvider implements OAuthClientProvider {
  OAuthTokens? _tokens;
  OAuthClientInformation? _clientInfo;
  String? _codeVerifier;
  final String _redirectUri;
  final String _clientName;

  InMemoryOAuthProvider({
    required String redirectUri,
    required String clientName,
  })  : _redirectUri = redirectUri,
        _clientName = clientName;

  @override
  Uri get redirectUrl => Uri.parse(_redirectUri);

  @override
  OAuthClientMetadata get clientMetadata => OAuthClientMetadata(
        clientName: _clientName,
        redirectUris: [_redirectUri],
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        scope: 'mcp:tools mcp:resources',
      );

  @override
  Future<OAuthTokens?> tokens() async => _tokens;

  @override
  Future<void> saveTokens(OAuthTokens tokens) async {
    _tokens = tokens;
    final expiryInfo =
        tokens.expiresAt != null ? ' (expires: ${tokens.expiresAt})' : '';
    print(
        '✓ Tokens saved: ${tokens.accessToken.substring(0, 20)}...$expiryInfo');
  }

  @override
  Future<OAuthClientInformation?> clientInformation() async => _clientInfo;

  @override
  Future<void> saveClientInformation(OAuthClientInformation info) async {
    _clientInfo = info;
    print('✓ Client registered: ${info.clientId}');
  }

  @override
  Future<void> saveCodeVerifier(String verifier) async {
    _codeVerifier = verifier;
    print('✓ PKCE verifier saved');
  }

  @override
  Future<String> codeVerifier() async {
    if (_codeVerifier == null) {
      throw Exception('Code verifier not found');
    }
    return _codeVerifier!;
  }

  @override
  Future<void> redirectToAuthorization(Uri authorizationUrl) async {
    print('\n🔐 Authorization Required');
    print('━' * 60);
    print('Opening browser for authorization...');
    print('\nURL: $authorizationUrl\n');
    print('Waiting for callback at: $_redirectUri');
    print('━' * 60);

    // Launch browser with authorization URL
    try {
      await _launchBrowser(authorizationUrl);
      print('✓ Browser launched successfully');
    } catch (e) {
      print('⚠️  Could not automatically open browser: $e');
      print('\nPlease manually open this URL:');
      print('$authorizationUrl\n');
    }
  }

  /// Launch the system browser with the authorization URL
  Future<void> _launchBrowser(Uri url) async {
    final urlString = url.toString();

    // Try different commands based on the platform
    if (Platform.isMacOS) {
      await Process.run('open', [urlString]);
    } else if (Platform.isLinux) {
      await Process.run('xdg-open', [urlString]);
    } else if (Platform.isWindows) {
      await Process.run('cmd', ['/c', 'start', urlString]);
    } else {
      throw UnsupportedError('Platform not supported');
    }
  }

  // Optional: Generate state for CSRF protection
  @override
  Future<String> Function()? get state => () async {
        // Generate cryptographically random state for CSRF protection
        final random = Random.secure();
        final bytes = List<int>.generate(32, (_) => random.nextInt(256));
        return base64UrlEncode(bytes);
      };

  // Optional: Handle credential invalidation
  @override
  Future<void> Function(String scope)? get invalidateCredentials =>
      (scope) async {
        print('⚠️  Invalidating credentials: $scope');
        switch (scope) {
          case 'all':
            _tokens = null;
            _clientInfo = null;
            _codeVerifier = null;
            break;
          case 'tokens':
            _tokens = null;
            break;
          case 'client':
            _clientInfo = null;
            break;
          case 'verifier':
            _codeVerifier = null;
            break;
        }
      };

  // Optional: Custom client authentication
  // Leave as null to use default OAuth 2.1 authentication methods
  @override
  Future<void> Function(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  )? get addClientAuthentication => null;
  // Example custom implementation:
  // => (headers, params, url, metadata) async {
  //      headers['X-Custom-Auth'] = 'my-custom-token';
  //    };

  // Optional: Custom resource URL validation
  // Leave as null to use default validation
  @override
  Future<Uri?> Function(Uri serverUrl, String? resource)?
      get validateResourceUrl => null;
  // Example custom implementation:
  // => (serverUrl, resource) async {
  //      return resource != null ? Uri.parse(resource) : null;
  //    };
}

/// Example MCP client with OAuth authentication.
///
/// This example demonstrates:
/// - Proper implementation of optional OAuth callbacks using nullable function getters
/// - Local HTTP server for OAuth callback handling
/// - Browser-based authorization flow
/// - Token storage and credential invalidation
Future<void> main() async {
  print('╔═══════════════════════════════════════════════════════════╗');
  print('║     MCP Dart SDK - OAuth 2.1 Authentication Example      ║');
  print('╚═══════════════════════════════════════════════════════════╝\n');

  // Step 1: Start local callback server
  final callbackServer = await OAuthCallbackServer.start();
  print('🌐 Callback server listening on: ${callbackServer.redirectUri}\n');

  // Step 2: Create OAuth provider with callback server
  final authProvider = InMemoryOAuthProvider(
    redirectUri: callbackServer.redirectUri,
    clientName: 'MCP Example Client',
  );

  // Step 3: Create transport with authentication
  final serverUrl = Uri.parse('http://localhost:10000/mcp');
  var transport = StreamableHttpClientTransport(
    serverUrl,
    opts: StreamableHttpClientTransportOptions(
      authProvider: authProvider,
    ),
  );

  // Step 4: Create MCP client
  final client = Client(
    Implementation(name: 'example-client', version: '1.0.0'),
  );

  print('📡 Connecting to MCP server: $serverUrl\n');

  try {
    // Step 5: Connect (this will trigger OAuth flow if needed)
    await client.connect(transport);

    print('\n✅ Connected successfully!');
    print(
        'Server: ${client.getServerVersion()?.name} ${client.getServerVersion()?.version}');
    print('Protocol: ${client.getServerCapabilities()}');

    // Step 6: Use the authenticated connection
    await demonstrateAuthenticatedUsage(client);

    // Step 7: Demonstrate token refresh checking
    print('\n🔍 Checking if tokens need refresh...');
    final needsRefresh = await shouldRefreshTokens(authProvider);
    print(
        needsRefresh ? '⚠️  Tokens need refresh' : '✓ Tokens are still valid');

    // Step 8: Demonstrate automatic token refresh on subsequent requests
    print('\n⏱️  Waiting 2 seconds before making another request...');
    await Future.delayed(Duration(seconds: 2));
    print('📡 Making second request (tokens will auto-refresh if needed)...');
    await demonstrateAuthenticatedUsage(client);
  } on UnauthorizedError {
    print('\n⏳ Waiting for authorization...');

    try {
      // Wait for the authorization code from the callback server
      final authCode = await callbackServer.authCodeCompleter.future
          .timeout(Duration(minutes: 5));

      print('✓ Authorization code received');

      // Complete the OAuth flow
      await transport.finishAuth(authCode);
      print('✓ Tokens obtained');

      // Create a new transport instance since the old one was already started
      transport = StreamableHttpClientTransport(
        serverUrl,
        opts: StreamableHttpClientTransportOptions(
          authProvider: authProvider,
        ),
      );

      // Retry connection with valid tokens
      await client.connect(transport);
      print('\n✅ Connected successfully!');
      print(
          'Server: ${client.getServerVersion()?.name} ${client.getServerVersion()?.version}');
      print('Protocol: ${client.getServerCapabilities()}');

      // Use the authenticated connection
      await demonstrateAuthenticatedUsage(client);

      // Demonstrate token refresh checking
      print('\n🔍 Checking if tokens need refresh...');
      final needsRefresh = await shouldRefreshTokens(authProvider);
      print(needsRefresh
          ? '⚠️  Tokens need refresh'
          : '✓ Tokens are still valid');

      // Demonstrate automatic token refresh on subsequent requests
      print('\n⏱️  Waiting 2 seconds before making another request...');
      await Future.delayed(Duration(seconds: 2));
      print('📡 Making second request (tokens will auto-refresh if needed)...');
      await demonstrateAuthenticatedUsage(client);
    } on TimeoutException {
      print('\n❌ Authorization timed out after 5 minutes');
    } on OAuthError catch (e) {
      print('\n❌ Failed to complete authorization: ${e.error}');
      if (e.errorDescription != null) {
        print('   ${e.errorDescription}');
      }
    }
  } on OAuthError catch (e) {
    print('\n❌ OAuth error: ${e.error}');
    if (e.errorDescription != null) {
      print('   ${e.errorDescription}');
    }
    if (e.errorUri != null) {
      print('   More info: ${e.errorUri}');
    }
  } catch (e) {
    print('\n❌ Connection error: $e');
  } finally {
    await client.close();
    await callbackServer.close();
  }
}

/// Demonstrates using an authenticated MCP client
Future<void> demonstrateAuthenticatedUsage(Client client) async {
  print('\n📋 Available Operations:');
  print('━' * 60);

  try {
    // List available tools
    final tools = await client.listTools();
    print('🔧 Tools: ${tools.tools.length}');
    for (final tool in tools.tools) {
      print('   - ${tool.name}: ${tool.description ?? "No description"}');
    }

    // List available resources
    final resources = await client.listResources();
    print('\n📚 Resources: ${resources.resources.length}');
    for (final resource in resources.resources) {
      print('   - ${resource.name}: ${resource.uri}');
    }

    // List available prompts
    final prompts = await client.listPrompts();
    print('\n💬 Prompts: ${prompts.prompts.length}');
    for (final prompt in prompts.prompts) {
      print('   - ${prompt.name}: ${prompt.description ?? "No description"}');
    }

    print('━' * 60);
  } catch (e) {
    print('\n⚠️  Error listing capabilities: $e');
  }
}

/// Local HTTP server to receive OAuth callbacks
///
/// This server listens on localhost and handles the OAuth redirect.
/// In production apps:
/// - Mobile: Use deep links (myapp://oauth/callback)
/// - Desktop: Use this local server approach or custom URL schemes
/// - Web: Use same-origin redirects
class OAuthCallbackServer {
  final HttpServer _server;
  final Completer<String> authCodeCompleter;

  OAuthCallbackServer._(this._server, this.authCodeCompleter);

  String get redirectUri => 'http://localhost:${_server.port}/oauth/callback';

  /// Start the callback server on a random available port
  static Future<OAuthCallbackServer> start() async {
    final completer = Completer<String>();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);

    // Handle incoming requests
    server.listen((HttpRequest request) async {
      final uri = request.uri;

      // Check if this is the OAuth callback
      if (uri.path == '/oauth/callback') {
        final code = uri.queryParameters['code'];
        final error = uri.queryParameters['error'];
        final errorDescription = uri.queryParameters['error_description'];

        if (code != null) {
          // Success - return friendly page and complete
          request.response
            ..statusCode = HttpStatus.ok
            ..headers.contentType = ContentType.html
            ..write(_successHtml());
          await request.response.close();

          if (!completer.isCompleted) {
            completer.complete(code);
          }
        } else if (error != null) {
          // Error - return error page and complete with error
          request.response
            ..statusCode = HttpStatus.ok
            ..headers.contentType = ContentType.html
            ..write(_errorHtml(error, errorDescription));
          await request.response.close();

          if (!completer.isCompleted) {
            completer.completeError(
              OAuthError(error, errorDescription),
            );
          }
        } else {
          // Invalid request
          request.response
            ..statusCode = HttpStatus.badRequest
            ..write('Missing required parameters');
          await request.response.close();
        }
      } else {
        // Unknown path
        request.response
          ..statusCode = HttpStatus.notFound
          ..write('Not found');
        await request.response.close();
      }
    });

    return OAuthCallbackServer._(server, completer);
  }

  /// Close the callback server
  Future<void> close() async {
    await _server.close();
  }

  static String _successHtml() {
    return '''
<!DOCTYPE html>
<html>
<head>
  <title>Authorization Successful</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .checkmark {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      display: block;
      stroke-width: 2;
      stroke: #4caf50;
      stroke-miterlimit: 10;
      margin: 0 auto 1rem;
      box-shadow: inset 0px 0px 0px #4caf50;
      animation: fill .4s ease-in-out .4s forwards, scale .3s ease-in-out .9s both;
    }
    .checkmark__circle {
      stroke-dasharray: 166;
      stroke-dashoffset: 166;
      stroke-width: 2;
      stroke-miterlimit: 10;
      stroke: #4caf50;
      fill: none;
      animation: stroke 0.6s cubic-bezier(0.65, 0, 0.45, 1) forwards;
    }
    .checkmark__check {
      transform-origin: 50% 50%;
      stroke-dasharray: 48;
      stroke-dashoffset: 48;
      animation: stroke 0.3s cubic-bezier(0.65, 0, 0.45, 1) 0.8s forwards;
    }
    @keyframes stroke {
      100% { stroke-dashoffset: 0; }
    }
    @keyframes scale {
      0%, 100% { transform: none; }
      50% { transform: scale3d(1.1, 1.1, 1); }
    }
    h1 { color: #333; margin-bottom: 0.5rem; }
    p { color: #666; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="container">
    <svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
      <circle class="checkmark__circle" cx="26" cy="26" r="25" fill="none"/>
      <path class="checkmark__check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8"/>
    </svg>
    <h1>Authorization Successful!</h1>
    <p>You have successfully authorized the application.</p>
    <p>You can close this window and return to the application.</p>
  </div>
</body>
</html>
''';
  }

  static String _errorHtml(String error, String? description) {
    return '''
<!DOCTYPE html>
<html>
<head>
  <title>Authorization Failed</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
    }
    .container {
      background: white;
      padding: 3rem;
      border-radius: 1rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
      max-width: 400px;
    }
    .error-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    h1 { color: #d32f2f; margin-bottom: 0.5rem; }
    p { color: #666; line-height: 1.5; }
    .error-details {
      background: #ffebee;
      padding: 1rem;
      border-radius: 0.5rem;
      margin-top: 1rem;
      font-family: monospace;
      font-size: 0.9rem;
      color: #c62828;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">❌</div>
    <h1>Authorization Failed</h1>
    <p>There was a problem authorizing the application.</p>
    ${description != null ? '<div class="error-details">$error: $description</div>' : '<div class="error-details">$error</div>'}
    <p style="margin-top: 1rem;">Please close this window and try again.</p>
  </div>
</body>
</html>
''';
  }
}
