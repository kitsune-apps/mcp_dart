/// Example demonstrating OAuth 2.1 authentication with MCP Dart SDK.
///
/// This example shows how to:
/// - Implement OAuthClientProvider for token storage
/// - Connect to an authenticated MCP server
/// - Handle authorization callbacks
/// - Implement secure token storage
library;

import 'dart:async';
import 'dart:convert';
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
    print('✓ Tokens saved: ${tokens.accessToken.substring(0, 20)}...');
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
    print('Please open this URL in your browser:');
    print('\n$authorizationUrl\n');
    print('After authorizing, you will be redirected to:');
    print('$_redirectUri?code=AUTHORIZATION_CODE');
    print('━' * 60);
  }

  @override
  Future<String> state() async {
    // Generate cryptographically random state for CSRF protection
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64UrlEncode(bytes);
  }

  @override
  Future<void> invalidateCredentials(String scope) async {
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
  }

  // Optional: Custom client authentication
  @override
  Future<void>? addClientAuthentication(
    Map<String, String> headers,
    Map<String, String> params,
    Uri url,
    AuthorizationServerMetadata? metadata,
  ) {
    // Use default authentication
    return null;
  }

  // Optional: Custom resource validation
  @override
  Future<Uri?>? validateResourceUrl(Uri serverUrl, String? resource) {
    // Use default validation
    return null;
  }
}

/// Example MCP client with OAuth authentication
Future<void> main() async {
  print('╔═══════════════════════════════════════════════════════════╗');
  print('║     MCP Dart SDK - OAuth 2.1 Authentication Example      ║');
  print('╚═══════════════════════════════════════════════════════════╝\n');

  // Step 1: Create OAuth provider
  final authProvider = InMemoryOAuthProvider(
    redirectUri: 'myapp://oauth/callback',
    clientName: 'MCP Example Client',
  );

  // Step 2: Create transport with authentication
  final serverUrl = Uri.parse('http://localhost:10000/mcp');
  final transport = StreamableHttpClientTransport(
    serverUrl,
    opts: StreamableHttpClientTransportOptions(
      authProvider: authProvider,
    ),
  );

  // Step 3: Create MCP client
  final client = Client(
    Implementation(name: 'example-client', version: '1.0.0'),
  );

  print('📡 Connecting to MCP server: $serverUrl\n');

  try {
    // Step 4: Connect (this will trigger OAuth flow if needed)
    await client.connect(transport);

    print('\n✅ Connected successfully!');
    print(
        'Server: ${client.getServerVersion()?.name} ${client.getServerVersion()?.version}');
    print('Protocol: ${client.getServerCapabilities()}');

    // Step 5: Use the authenticated connection
    await demonstrateAuthenticatedUsage(client);
  } on UnauthorizedError catch (e) {
    print('\n❌ Authorization failed: ${e.message}');
    print('\nTo complete authorization:');
    print('1. Open the URL shown above in your browser');
    print('2. Log in and authorize the application');
    print('3. Copy the authorization code from the redirect URL');
    print('4. Call: await transport.finishAuth(authorizationCode)');
    print('5. Retry: await client.connect(transport)');
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

/// Helper function to handle OAuth callback (would be called by your deep link handler)
Future<void> handleOAuthCallback(
  StreamableHttpClientTransport transport,
  Client client,
  String authorizationCode,
) async {
  print('\n🔄 Processing authorization callback...');

  try {
    // Complete the OAuth flow
    await transport.finishAuth(authorizationCode);
    print('✓ Authorization code exchanged for tokens');

    // Retry connection with valid tokens
    await client.connect(transport);
    print('✓ Connected successfully');
  } on OAuthError catch (e) {
    print('❌ Failed to exchange authorization code: ${e.error}');
    if (e.errorDescription != null) {
      print('   ${e.errorDescription}');
    }
  }
}
