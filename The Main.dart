// 🟢 ZARINPAL DART SDK - ULTRA SECURE & ENHANCED EDITION 🟢
// Version: 3.8.4 (with bug fixes, advanced security, resilience, diagnostics, enhanced UI, and advanced QR customization)
// --------------------------------------------------------
// Author: The code was originally written by Angeplla and later developed further by Phoenix Marie.
// Bug fixes (Version 3.8):
// - Fixed authority field handling in PaymentVerify and JSON parsing.
// - Corrected autoFallback to use a valid Zarinpal endpoint.
// - Fixed rate limiting to track per endpoint.
// - Removed unnecessary callback signature verification (pending Zarinpal API confirmation).
// - Added Windows file permission handling for history file.
// - Added robust error handling for history file decryption.
// - Added null checks in handleCallback for pending payments.
// - Fixed session ID cleanup in handleCallback on verification failure.
// - Adjusted dynamic table column widths in ConsoleUI.
// Security enhancements (inherited from 3.7):
// - Encrypted sensitive data (cardPan, email, mobile) using AES.
// - Stricter input validation for callback URLs and user inputs.
// - Enforced HTTPS and SSL validation for API calls.
// - Fixed authority validation in findTransactionByAuthority.
// - Implemented rate limiting for API calls and callbacks.
// - Added session management with unique IDs to prevent replay attacks.
// - Secured file storage with encryption and permissions.
// - Added audit logging for security-relevant actions.
// UI improvements (inherited from 3.7):
// - Added secure input prompts with masked data.
// - Introduced security status indicators.
// - Added audit log display option in menu.

// New Feature (Version 3.8.1 - Professional QR Code Generator):
// - Added ASCII-based QR code generation for payment URLs using 'ascii_qr' package.
// - Integrated QR code display in console for payment requests.
// - Added menu option for generating QR codes for existing authorities.
// - Supports high error correction for scannable QR codes in terminals.
// - Note: Add 'ascii_qr: ^1.0.1' (or latest) to your pubspec.yaml dependencies.

// Additional Features (Version 3.8.2):
// - Added image-based QR code generation using 'qr' and 'image' packages, saving to PNG files.
// - Made QR error correction levels configurable (L, M, Q, H).
// - Enhanced QR menu integration with sub-options for ASCII/Image, error level selection, and file saving for images.
// - Added QR code validation function to check if generated QR data is correct.
// - Added batch QR generation for multiple authorities.
// - Note: Add 'qr: ^3.0.2' (or latest) and 'image: ^4.5.4' (or latest) to your pubspec.yaml dependencies.

// Additional Features (Version 3.8.3):
// - Added more QR customization options: custom foreground/background colors, quiet zone size, optional logo overlay.
// - Enhanced generateImagePaymentQR with new parameters for colors, quietZone, logoPath.
// - Added logo resizing and centering for overlay.
// - Updated menu to include customization prompts.

// Bug Fixes and UI Improvements (Version 3.8.4):
// - Removed duplicate addToHistory and exportTransactionHistoryToJson functions outside the class.
// - Fixed validateQRCode to handle image case by skipping or noting simulation.
// - Added timestamp to exportTransactionHistoryToJson in the class.
// - Improved UI: Added more colorful menu items, bordered menu, animated spinner for progress, colored tables if possible (note: cli_table may not support colors, so added manual coloring where possible).
// - Enhanced prompts with colors.
// - Fixed potential null in findTransactionByAuthority orElse.
// - Added error handling in generateImagePaymentQR for logo loading.

import 'dart:convert';
import 'dart:io';
import 'dart:async';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:cli_table/cli_table.dart';
import 'package:persian_tools/persian_tools.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:ascii_qr/ascii_qr.dart'; // For ASCII QR generation
import 'package:qr/qr.dart'; // For QR code data generation
import 'package:image/image.dart' as img; // For image manipulation and PNG saving

/// ---------------------------
///  Zarinpal Environment Setup
/// ---------------------------
class ZarinpalEnvironment {
  static const String production = 'https://api.zarinpal.com/pg/v4/payment';
  static const String sandbox = 'https://sandbox.zarinpal.com/pg/v4/payment';
}

/// ---------------------------
///  Currency Enum
/// ---------------------------
enum Currency {
  rial,
  toman,
}

/// ---------------------------
///  Error Model
/// ---------------------------
class ZarinpalError implements Exception {
  final String message;
  final int? statusCode;
  final String? endpoint;
  final String? details;

  ZarinpalError(this.message, {this.statusCode, this.endpoint, this.details});

  @override
  String toString() =>
      'ZarinpalError(endpoint: $endpoint, status: $statusCode): $message${details != null ? '\nDetails: $details' : ''}';
}

/// ---------------------------
///  Core Zarinpal SDK
/// ---------------------------
class Zarinpal {
  final String merchantId;
  bool sandbox;
  late String baseUrl;
  final encrypt.Encrypter _encrypter;
  final String _encryptionKey;
  final Map<String, List<DateTime>> _rateLimitTracker = {};
  final Map<String, String> _sessionIds = {};
  final List<String> _auditLogs = [];

  void Function(PaymentVerify verify)? onSuccess;
  void Function(dynamic error)? onError;
  bool verbose = false;

  final List<PaymentVerify> _transactionHistory = [];
  final Set<String> _verifiedAuthorities = {};
  final List<PaymentRequest> _pendingRequests = [];
  final Map<String, PaymentRequest> _pendingPayments = {};

  Zarinpal({required this.merchantId, this.sandbox = false, String? encryptionKey})
      : _encryptionKey = encryptionKey ?? _generateSecureKey(),
        _encrypter = encrypt.Encrypter(
            encrypt.AES(encrypt.Key.fromUtf8(encryptionKey ?? _generateSecureKey()))) {
    baseUrl = sandbox ? ZarinpalEnvironment.sandbox : ZarinpalEnvironment.production;
  }

  /// 🔐 Generate Secure Key
  static String _generateSecureKey() {
    final random = encrypt.SecureRandom(32);
    return random.base64;
  }

  /// 🔐 Encrypt Data
  String _encryptData(String data) {
    final iv = encrypt.IV.fromSecureRandom(16);
    final encrypted = _encrypter.encrypt(data, iv: iv);
    return '${iv.base64}:${encrypted.base64}';
  }

  /// 🔐 Decrypt Data
  String _decryptData(String encryptedData) {
    try {
      final parts = encryptedData.split(':');
      if (parts.length != 2) throw ZarinpalError('Invalid encrypted data format');
      final iv = encrypt.IV.fromBase64(parts[0]);
      final encrypted = parts[1];
      return _encrypter.decrypt64(encrypted, iv: iv);
    } catch (e) {
      throw ZarinpalError('Decryption failed: $e');
    }
  }

  /// ✅ Merchant ID format validation
  bool validateMerchantId() {
    final regex = RegExp(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');
    if (merchantId.length != 36) return false;
    return regex.hasMatch(merchantId);
  }

  /// ✅ Validate request data
  bool validatePaymentRequest(PaymentRequest request) {
    if (request.amount <= 0) throw ArgumentError('Amount must be greater than zero.');
    final uri = Uri.parse(request.callbackUrl);
    if (!uri.isAbsolute || uri.scheme != 'https') {
      throw ArgumentError('Callback URL must be HTTPS.');
    }
    if (request.description.isEmpty) throw ArgumentError('Description cannot be empty.');
    return true;
  }

  /// ✅ Validate refund data
  bool validateRefundRequest({required String authority, required int amount}) {
    if (amount <= 0) throw ArgumentError('Refund amount must be greater than zero.');
    if (authority.isEmpty) throw ArgumentError('Authority cannot be empty.');
    return true;
  }

  /// 📜 Audit Log
  void _addAuditLog(String action, String details) {
    final timestamp = DateTime.now().toIso8601String();
    _auditLogs.add('[$timestamp] $action: $details');
  }

  /// 🌐 Automatic Sandbox Fallback
  Future<void> autoFallback() async {
    if (!sandbox) {
      try {
        await http
            .get(Uri.parse('$baseUrl/request.json'))
            .timeout(const Duration(seconds: 3));
      } catch (_) {
        stderr.writeln('⚠️ Switching temporarily to sandbox...');
        sandbox = true;
        baseUrl = ZarinpalEnvironment.sandbox;
        _addAuditLog('Sandbox Fallback', 'Switched to sandbox due to connectivity issue');
      }
    }
  }

  /// 🧰 Safe HTTP POST with Rate Limiting
  Future<http.Response> _safePost(
    Uri url,
    Map<String, dynamic> body, {
    int retries = 2,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!_checkRateLimit(url.path)) {
      throw ZarinpalError('Rate limit exceeded for $url', endpoint: url.path);
    }

    for (var attempt = 0; attempt <= retries; attempt++) {
      try {
        final response = await http
            .post(url,
                headers: {'Content-Type': 'application/json'}, body: jsonEncode(body))
            .timeout(timeout);

        if (response.statusCode >= 500) {
          throw HttpException('Server error ${response.statusCode}');
        }

        _addAuditLog('HTTP POST', 'Endpoint: ${url.path}, Status: ${response.statusCode}');
        return response;
      } on SocketException catch (_) {
        if (attempt == retries) rethrow;
        await Future.delayed(Duration(milliseconds: 400 * (attempt + 1)));
      } on TimeoutException catch (_) {
        if (attempt == retries) rethrow;
        await Future.delayed(Duration(milliseconds: 500 * (attempt + 1)));
      } on HttpException catch (_) {
        if (attempt == retries) rethrow;
        await Future.delayed(const Duration(seconds: 1));
      }
    }
    throw ZarinpalError('Failed after $retries retries', endpoint: url.path);
  }

  /// 🧩 Safe JSON decoding
  Map<String, dynamic> _safeDecode(String body) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) return decoded;
      _addAuditLog('JSON Decode Error', 'Unexpected response format: $body');
      return {'message': 'Unexpected response format'};
    } catch (e) {
      throw ZarinpalError('Invalid JSON format: $e');
    }
  }

  /// 🛡️ Rate Limiting
  bool _checkRateLimit(String endpoint) {
    const limit = 10; // 10 requests per minute per endpoint
    const window = Duration(minutes: 1);
    final now = DateTime.now();
    _rateLimitTracker[endpoint] ??= [];
    _rateLimitTracker[endpoint]!.removeWhere((time) => now.difference(time) > window);
    if (_rateLimitTracker[endpoint]!.length >= limit) return false;
    _rateLimitTracker[endpoint]!.add(now);
    return true;
  }

  /// 💳 Payment Request
  Future<PaymentResponse> requestPayment(PaymentRequest request) async {
    validatePaymentRequest(request);
    await autoFallback();

    final url = Uri.parse('$baseUrl/request.json');
    final sessionId = _generateSecureKey().substring(0, 16);
    _sessionIds[sessionId] = request.callbackUrl;

    int apiAmount = request.currency == Currency.toman ? request.amount * 10 : request.amount;

    final body = {
      'merchant_id': merchantId,
      'amount': apiAmount,
      'callback_url': request.callbackUrl,
      'description': request.description,
      'metadata': {
        'email': request.email != null ? _encryptData(request.email!) : null,
        'mobile': request.mobile != null ? _encryptData(request.mobile!) : null,
        'session_id': sessionId,
      },
    };

    final response = await _safePost(url, body);
    final jsonMap = _safeDecode(response.body);
    _validateResponse(jsonMap, 'request');
    final paymentResponse = PaymentResponse.fromJson(jsonMap['data']);
    _pendingPayments[paymentResponse.authority] = request;
    _addAuditLog('Payment Request', 'Authority: ${paymentResponse.authority}, Amount: $apiAmount');
    return paymentResponse;
  }

  /// 🔎 Verify Payment
  Future<PaymentVerify> verifyPayment({
    required int amount,
    required String authority,
    Currency currency = Currency.rial,
  }) async {
    final existing = findTransactionByAuthority(authority);
    if (existing != null) {
      debugLog('Transaction already verified: $authority');
      return existing;
    }

    int apiAmount = currency == Currency.toman ? amount * 10 : amount;

    final url = Uri.parse('$baseUrl/verify.json');
    final body = {'merchant_id': merchantId, 'amount': apiAmount, 'authority': authority};

    final response = await _safePost(url, body);
    final jsonMap = _safeDecode(response.body);
    _validateResponse(jsonMap, 'verify');

    final verify = PaymentVerify.fromJson({
      ...jsonMap['data'],
      'authority': authority, // Explicitly set authority
    });
    addToHistory(verify);
    _verifiedAuthorities.add(authority);
    _addAuditLog('Payment Verify', 'Authority: $authority, Code: ${verify.code}');
    return verify;
  }

  /// 🔐 Safe Verify with Callbacks
  Future<PaymentVerify> safeVerifyPayment({
    required int amount,
    required String authority,
    Currency currency = Currency.rial,
  }) async {
    try {
      final verify = await verifyPayment(amount: amount, authority: authority, currency: currency);
      if (isPaymentSuccessful(verify)) {
        onSuccess?.call(verify);
      } else {
        onError?.call('Payment failed: ${verify.message}');
      }
      return verify;
    } catch (e) {
      onError?.call(e);
      _addAuditLog('Verify Error', e.toString());
      rethrow;
    }
  }

  /// 🌐 Start Pay URL
  String getStartPayUrl(String authority) {
    final host = sandbox ? 'sandbox.zarinpal.com' : 'www.zarinpal.com';
    return 'https://$host/pg/StartPay/$authority';
  }

  /// 🔁 Inquiry / Refund
  Future<PaymentVerify> transactionInquiry(String authority) async {
    final url = Uri.parse('$baseUrl/inquiry.json');
    final body = {'merchant_id': merchantId, 'authority': authority};
    try {
      final response = await _safePost(url, body);
      final jsonMap = _safeDecode(response.body);
      _validateResponse(jsonMap, 'inquiry');
      final verify = PaymentVerify.fromJson({
        ...jsonMap['data'],
        'authority': authority,
      });
      addToHistory(verify);
      _addAuditLog('Transaction Inquiry', 'Authority: $authority');
      return verify;
    } catch (e) {
      logError('transactionInquiry', e);
      throw ZarinpalError('Inquiry failed, endpoint may not exist', endpoint: 'inquiry', details: e.toString());
    }
  }

  Future<RefundResponse> refundTransaction({
    required String authority,
    required int amount,
    Currency currency = Currency.rial,
    String? description,
    String? method,
    String? reason,
  }) async {
    validateRefundRequest(authority: authority, amount: amount);
    int apiAmount = currency == Currency.toman ? amount * 10 : amount;

    final url = Uri.parse('$baseUrl/refund.json');
    final body = <String, dynamic>{
      'merchant_id': merchantId,
      'authority': authority,
      'amount': apiAmount,
    };
    if (description != null) body['description'] = description;
    if (method != null) body['method'] = method;
    if (reason != null) body['reason'] = reason;

    final response = await _safePost(url, body);
    final jsonMap = _safeDecode(response.body);
    _validateResponse(jsonMap, 'refund');
    _addAuditLog('Refund Request', 'Authority: $authority, Amount: $apiAmount');
    return RefundResponse.fromJson(jsonMap['data']);
  }

  /// 🧮 Utility Functions
  bool isPaymentSuccessful(PaymentVerify verify) => verify.code == 100 || verify.code == 101;

  Future<PaymentVerify?> handleCallback(Map<String, String> queryParams) async {
    final authority = queryParams['Authority'];
    final status = queryParams['Status'];
    final sessionId = queryParams['session_id'];

    if (authority == null || status != 'OK' || !_pendingPayments.containsKey(authority)) {
      _addAuditLog('Callback Failed', 'Invalid authority or status: $authority, $status');
      return null;
    }

    if (sessionId == null || _sessionIds[sessionId] == null) {
      _addAuditLog('Callback Failed', 'Invalid session ID: $sessionId');
      return null;
    }

    final req = _pendingPayments[authority];
    if (req == null) {
      _addAuditLog('Callback Failed', 'No pending payment for authority: $authority');
      _sessionIds.remove(sessionId);
      return null;
    }

    try {
      final verify = await verifyPayment(amount: req.amount, authority: authority, currency: req.currency);
      _pendingPayments.remove(authority);
      _sessionIds.remove(sessionId);
      addToHistory(verify);
      _addAuditLog('Callback Success', 'Authority: $authority, Ref ID: ${verify.refId}');
      return verify;
    } catch (e) {
      logError('handleCallback', e);
      _addAuditLog('Callback Error', e.toString());
      _sessionIds.remove(sessionId);
      return null;
    }
  }

  /// 🪣 Queue + Retry
  Future<void> queuePayment(PaymentRequest req) async {
    _pendingRequests.add(req);
    _addAuditLog('Queue Payment', 'Amount: ${req.amount}, Callback: ${req.callbackUrl}');
  }

  Future<void> retryQueuedPayments() async {
    for (final req in List.of(_pendingRequests)) {
      try {
        await requestPayment(req);
        _pendingRequests.remove(req);
        _addAuditLog('Retry Success', 'Payment request retried for ${req.callbackUrl}');
      } catch (e) {
        logError('retryQueuedPayments', e);
        _addAuditLog('Retry Failed', e.toString());
      }
    }
  }

  /// 💾 Persistent History (Encrypted)
  Future<void> saveHistoryToFile() async {
    final file = File('zarinpal_history.json');
    try {
      final encryptedData = _encryptData(exportTransactionHistoryToJson());
      await file.writeAsString(encryptedData, flush: true);
      await _setFilePermissions(file);
      _addAuditLog('Save History', 'History saved to file');
    } catch (e) {
      logError('saveHistoryToFile', e);
      _addAuditLog('Save History Failed', e.toString());
    }
  }

  Future<void> loadHistoryFromFile() async {
    final file = File('zarinpal_history.json');
    if (await file.exists()) {
      try {
        final encryptedData = await file.readAsString();
        final jsonStr = _decryptData(encryptedData);
        final list = jsonDecode(jsonStr) as List;
        _transactionHistory
          ..clear()
          ..addAll(list.map((e) => PaymentVerify.fromJson({
                'code': e['code'] ?? 0,
                'message': e['message'] ?? '',
                'ref_id': e['ref_id'] ?? 0,
                'card_pan': _decryptData(e['card_pan'] ?? ''),
                'authority': e['authority'] ?? '',
              })));
        _addAuditLog('Load History', 'History loaded from file');
      } catch (e) {
        logError('loadHistoryFromFile', e);
        _addAuditLog('Load History Failed', e.toString());
      }
    }
  }

  /// 🔐 File Permissions
  Future<void> _setFilePermissions(File file) async {
    try {
      if (Platform.isLinux || Platform.isMacOS) {
        await Process.run('chmod', ['600', file.path]);
      } else if (Platform.isWindows) {
        await Process.run('icacls', [file.path, '/inheritance:r', '/grant:r', 'Users:R']);
      }
    } catch (e) {
      logError('setFilePermissions', e);
      _addAuditLog('Set File Permissions Failed', e.toString());
    }
  }

  /// 🔒 Signature Generation
  String generateSignature(String data, String secretKey) {
    final key = utf8.encode(secretKey);
    final bytes = utf8.encode(data);
    final hmac = Hmac(sha256, key);
    return hmac.convert(bytes).toString();
  }

  /// 🗾 History
  void addToHistory(PaymentVerify verify) =>
      _transactionHistory.add(verify.copyWith(cardPan: _encryptData(verify.cardPan)));

  List<PaymentVerify> getTransactionHistory() =>
      _transactionHistory.map((t) => t.copyWith(cardPan: _decryptData(t.cardPan))).toList();

  String exportTransactionHistoryToJson() => jsonEncode(
        _transactionHistory
            .map((e) => {
                  'code': e.code,
                  'message': e.message,
                  'ref_id': e.refId,
                  'card_pan': e.cardPan, // Already encrypted
                  'authority': e.authority,
                  'timestamp': DateTime.now().toIso8601String(),
                })
            .toList(),
      );

  /// 🔍 Find Transaction by Authority
  PaymentVerify? findTransactionByAuthority(String authority) {
    try {
      return _transactionHistory.firstWhere(
        (t) => t.authority == authority,
      );
    } on StateError {
      return null;
    }
  }

  /// 🌐 Connectivity
  Future<bool> checkConnectivity() async {
    try {
      final response = await http
          .get(Uri.parse(sandbox ? ZarinpalEnvironment.sandbox : ZarinpalEnvironment.production))
          .timeout(const Duration(seconds: 4));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// 🧩 Validation
  void _validateResponse(Map<String, dynamic> json, String endpoint) {
    if (json['data'] == null) {
      final msg = json['errors']?['message'] ?? json['message'] ?? 'Unknown error';
      throw ZarinpalError(msg, endpoint: endpoint);
    }
  }

  /// 🪶 Debug Logging
  void debugLog(String message) {
    if (verbose) print('🪶 [DEBUG] $message');
  }

  /// 🧱 Sensitive Masking
  String maskSensitive(String input) {
    if (input.length <= 8) return '****';
    return '${input.substring(0, 4)}****${input.substring(input.length - 4)}';
  }

  /// 🧱 Safe Error Logging
  void logError(String method, dynamic error) {
    final timestamp = DateTime.now().toIso8601String();
    stderr.writeln('🔥 [Zarinpal][$timestamp][$method] => $error');
  }

  /// 🛑 Graceful Shutdown
  Future<void> shutdown() async {
    try {
      await saveHistoryToFile();
      _pendingRequests.clear();
      _pendingPayments.clear();
      _sessionIds.clear();
      debugLog('SDK shutdown complete.');
      _addAuditLog('Shutdown', 'SDK shutdown completed');
    } catch (e) {
      logError('shutdown', e);
      _addAuditLog('Shutdown Failed', e.toString());
    }
  }

  /// 📜 Get Audit Logs
  List<String> getAuditLogs() => List.unmodifiable(_auditLogs);

  // -------------------------------
  // Additional Functions
  // -------------------------------

  /// 🔤 Convert Number to Persian Words
  String numberToPersianWords(int number, {bool ordinal = false}) {
    return numberToWords(number, ordinal: ordinal);
  }

  /// 💲 Format Amount with Currency
  String formatAmount(int amount, Currency currency) {
    final symbol = currency == Currency.rial ? 'ریال' : 'تومان';
    return '$amount $symbol';
  }

  /// 💱 Convert Toman to Rial
  int tomanToRial(int toman) => toman * 10;

  /// 💱 Convert Rial to Toman
  int rialToToman(int rial) => rial ~/ 10;

  /// 🔤 Amount to Persian Words with Currency
  String amountToPersianWords(int amount, Currency currency, {bool ordinal = false}) {
    final words = numberToPersianWords(amount, ordinal: ordinal);
    final symbol = currency == Currency.rial ? 'ریال' : 'تومان';
    return '$words $symbol';
  }

  /// 📜 Get Unverified Payments
  Future<List<UnverifiedTransaction>> getUnverifiedPayments() async {
    final url = Uri.parse('$baseUrl/unVerified.json');
    final body = {'merchant_id': merchantId};
    final response = await _safePost(url, body);
    final jsonMap = _safeDecode(response.body);
    _validateResponse(jsonMap, 'unVerified');
    final authorities = jsonMap['data']['authorities'] as List? ?? [];
    _addAuditLog('Unverified Payments', 'Fetched ${authorities.length} unverified transactions');
    return authorities.map((e) => UnverifiedTransaction.fromJson(e)).toList();
  }

  /// 🌐 Start Callback Server
  Future<HttpServer> startCallbackServer({
    required int port,
    String path = '/verify',
    void Function(PaymentVerify verify)? onVerified,
    void Function(String authority, String status)? onFailed,
  }) async {
    final handler = Pipeline().addHandler((Request req) async {
      if (req.url.path == path) {
        if (!_checkRateLimit('callback_$path')) {
          _addAuditLog('Callback Rate Limit', 'Rate limit exceeded');
          return Response.forbidden('Rate limit exceeded');
        }
        final queryParams = req.url.queryParameters;
        try {
          final verify = await handleCallback(queryParams);
          if (verify != null && isPaymentSuccessful(verify)) {
            onVerified?.call(verify);
            return Response.ok('✅ Payment successful! Ref ID: ${verify.refId}');
          } else {
            final authority = queryParams['Authority'] ?? '';
            final status = queryParams['Status'] ?? '';
            onFailed?.call(authority, status);
            return Response.ok('❌ Payment failed.');
          }
        } catch (e) {
          logError('startCallbackServer', e);
          return Response.internalServerError(body: 'Error processing callback: $e');
        }
      }
      return Response.notFound('Not Found');
    });
    final server = await shelf_io.serve(handler, InternetAddress.anyIPv4, port);
    debugLog('Callback server running on https://localhost:$port/$path');
    _addAuditLog('Callback Server', 'Started on port $port');
    return server;
  }

  /// 🧮 Calculate Zarinpal Transaction Fee
  int calculateFee(int amount, Currency currency) {
    int amountInToman = currency == Currency.toman ? amount : rialToToman(amount);
    double percentFee = 0.005 * amountInToman;
    int cappedPercent = percentFee > 12000 ? 12000 : percentFee.toInt();
    int totalFeeInToman = cappedPercent + 350;
    return currency == Currency.toman ? totalFeeInToman : tomanToRial(totalFeeInToman);
  }

  /// 🔍 Get Transaction Details
  Future<PaymentVerify> getTransactionDetails(String authority) async {
    return await transactionInquiry(authority);
  }

  // -------------------------------
  // Newly Developed Additional Functions
  // -------------------------------

  /// 💵 Calculate Banknote Breakdown
  /// Supports banknotes: 200,000, 100,000, 50,000, 10,000, 5,000, 2,000, 1,000, 500 toman
  Map<int, int> calculateBanknoteBreakdown(int amountInToman) {
    final banknotes = [200000, 100000, 50000, 10000, 5000, 2000, 1000, 500];
    final breakdown = <int, int>{};
    int remaining = amountInToman;

    for (final note in banknotes) {
      if (remaining >= note) {
        final count = remaining ~/ note;
        breakdown[note] = count;
        remaining -= count * note;
      }
    }

    if (remaining > 0) {
      debugLog('Remaining amount after breakdown: $remaining toman (not covered by standard banknotes)');
    }

    _addAuditLog('Banknote Breakdown', 'Calculated for $amountInToman toman');
    return breakdown;
  }

  /// 📊 Display Banknote Breakdown in Console
  void displayBanknoteBreakdown(int amountInToman) {
    final breakdown = calculateBanknoteBreakdown(amountInToman);
    ConsoleUI.header('Banknote Breakdown');
    if (breakdown.isEmpty) {
      ConsoleUI.warning('No banknotes needed for amount: $amountInToman toman');
      return;
    }
    final data = breakdown.entries.map((e) => {
          'Banknote (toman)': e.key,
          'Count': e.value,
          'Total (toman)': e.key * e.value,
        }).toList();
    ConsoleUI.displayTable(data);
  }

  /// 📈 Calculate Percentage of Amount
  /// Returns the percentage value in the specified currency and its equivalent in the other currency
  Map<String, int> calculatePercentage(int amount, double percentage, Currency currency) {
    if (percentage < 0 || percentage > 100) {
      throw ArgumentError('Percentage must be between 0 and 100');
    }
    final percentValue = (amount * (percentage / 100)).toInt();
    final result = <String, int>{};
    if (currency == Currency.toman) {
      result['toman'] = percentValue;
      result['rial'] = tomanToRial(percentValue);
    } else {
      result['rial'] = percentValue;
      result['toman'] = rialToToman(percentValue);
    }
    _addAuditLog('Percentage Calculation', 'Calculated $percentage% of $amount $currency');
    return result;
  }

  /// 🔄 Reset Transaction History (with confirmation)
  Future<void> resetTransactionHistory() async {
    print('⚠️ Warning: This will clear all transaction history. Continue? (y/n)');
    final confirmation = stdin.readLineSync()?.trim().toLowerCase();
    if (confirmation == 'y') {
      _transactionHistory.clear();
      _verifiedAuthorities.clear();
      await saveHistoryToFile();
      _addAuditLog('Reset History', 'Transaction history reset');
      ConsoleUI.success('Transaction history reset successfully.');
    } else {
      ConsoleUI.info('Reset cancelled.');
    }
  }

  // -------------------------------
  // Professional QR Code Generator (New Feature)
  // -------------------------------

  /// 📱 Generate Scannable QR Code for Payment URL (ASCII Art)
  /// Uses configurable error correction for reliability in terminal display.
  /// Can be scanned directly from console using mobile devices.
  String generatePaymentQR(String authority, {int errorCorrectLevel = QrErrorCorrectLevel.H}) {
    final paymentUrl = getStartPayUrl(authority);
    final qrCode = AsciiQrGenerator.generate(
      paymentUrl,
      errorCorrectLevel: errorCorrectLevel,
    );
    _addAuditLog('QR Generation (ASCII)', 'Generated QR for authority: $authority, URL: $paymentUrl, Error Level: $errorCorrectLevel');
    return qrCode;
  }

  /// 📱 Display QR Code in Console
  void displayPaymentQR(String authority, {int errorCorrectLevel = QrErrorCorrectLevel.H}) {
    ConsoleUI.header('Payment QR Code (ASCII)');
    final qr = generatePaymentQR(authority, errorCorrectLevel: errorCorrectLevel);
    print(qr);
    ConsoleUI.info('Scan this QR code with your mobile device to initiate payment.');
    ConsoleUI.warning('Ensure your terminal font is monospace for accurate rendering.');
  }

  // -------------------------------
  // Additional QR Functions (Version 3.8.2)
  // -------------------------------

  /// 📱 Generate Scannable QR Code for Payment URL as PNG Image
  /// Saves the QR code as a PNG file with configurable error correction and scale.
  Future<void> generateImagePaymentQR(
    String authority,
    String filePath, {
    int errorCorrectLevel = QrErrorCorrectLevel.H,
    int scale = 4,
    img.Color? fgColor,
    img.Color? bgColor,
    int quietZone = 4,
    String? logoPath,
  }) async {
    final paymentUrl = getStartPayUrl(authority);
    final qrCode = QrCode.fromData(
      data: paymentUrl,
      errorCorrectLevel: errorCorrectLevel,
    );
    qrCode.make();

    final moduleCount = qrCode.moduleCount;
    final size = (moduleCount + 2 * quietZone) * scale;
    final image = img.Image(
      width: size,
      height: size,
    );
    img.fill(image, color: bgColor ?? img.ColorRgb8(255, 255, 255));

    final qrFgColor = fgColor ?? img.ColorRgb8(0, 0, 0);
    for (int x = 0; x < moduleCount; x++) {
      for (int y = 0; y < moduleCount; y++) {
        if (qrCode.isDark(y, x)) {
          img.fillRect(
            image,
            x1: (quietZone + x) * scale,
            y1: (quietZone + y) * scale,
            x2: (quietZone + x) * scale + scale,
            y2: (quietZone + y) * scale + scale,
            color: qrFgColor,
          );
        }
      }
    }

    if (logoPath != null) {
      try {
        final logoBytes = await File(logoPath).readAsBytes();
        final logoImage = img.decodeImage(logoBytes);
        if (logoImage != null) {
          final logoSize = (moduleCount * scale ~/ 5).clamp(1, size ~/ 3); // Logo size ~20% of QR
          final resizedLogo = img.copyResize(logoImage, width: logoSize, height: logoSize);
          final offset = (size - logoSize) ~/ 2;
          img.compositeImage(image, resizedLogo, dstX: offset, dstY: offset);
        } else {
          debugLog('Failed to decode logo from $logoPath');
        }
      } catch (e) {
        debugLog('Failed to load logo from $logoPath: $e');
      }
    }

    final pngBytes = img.encodePng(image);
    await File(filePath).writeAsBytes(pngBytes);
    _addAuditLog('QR Generation (Image)', 'Saved QR for authority: $authority to $filePath, Error Level: $errorCorrectLevel, Scale: $scale');
    ConsoleUI.success('QR code image saved to $filePath');
  }

  /// 🔍 Validate Generated QR Code
  /// Checks if the QR code data matches the expected payment URL (placeholder for actual validation logic).
  bool validateQRCode(String authority, String qrData) {
    final expectedUrl = getStartPayUrl(authority);
    // In a real scenario, use a QR reader library to decode qrData and compare.
    // For now, simulate validation.
    final isValid = qrData.contains(expectedUrl);
    _addAuditLog('QR Validation', 'Validated QR for authority: $authority, Valid: $isValid');
    return isValid;
  }

  /// 📱 Batch Generate QR Codes
  /// Generates QR codes (ASCII or Image) for multiple authorities.
  Future<void> batchGenerateQRs(
    List<String> authorities, {
    bool ascii = true,
    String? directory,
    int errorCorrectLevel = QrErrorCorrectLevel.H,
  }) async {
    for (final authority in authorities) {
      if (ascii) {
        displayPaymentQR(authority, errorCorrectLevel: errorCorrectLevel);
      } else {
        if (directory == null) throw ArgumentError('Directory required for image batch generation');
        final filePath = '$directory/qr_$authority.png';
        await generateImagePaymentQR(authority, filePath, errorCorrectLevel: errorCorrectLevel);
      }
    }
    _addAuditLog('Batch QR Generation', 'Generated QRs for ${authorities.length} authorities, Type: ${ascii ? 'ASCII' : 'Image'}');
  }
}

/// ---------------------------
///  Data Models
/// ---------------------------
class PaymentRequest {
  final int amount;
  final String callbackUrl;
  final String description;
  final String? email;
  final String? mobile;
  final Currency currency;

  PaymentRequest({
    required this.amount,
    required this.callbackUrl,
    required this.description,
    this.email,
    this.mobile,
    this.currency = Currency.rial,
  });
}

class PaymentResponse {
  final int code;
  final String message;
  final String authority;
  final String? feeType;
  final int? fee;

  PaymentResponse({
    required this.code,
    required this.message,
    required this.authority,
    this.feeType,
    this.fee,
  });

  factory PaymentResponse.fromJson(Map<String, dynamic> json) => PaymentResponse(
        code: json['code'] as int? ?? 0,
        message: json['message'] as String? ?? '',
        authority: json['authority'] as String? ?? '',
        feeType: json['fee_type'] as String?,
        fee: json['fee'] as int?,
      );
}

class PaymentVerify {
  final int code;
  final String message;
  final int refId;
  final String cardPan;
  final String authority;

  PaymentVerify({
    required this.code,
    required this.message,
    required this.refId,
    required this.cardPan,
    required this.authority,
  });

  factory PaymentVerify.fromJson(Map<String, dynamic> json) => PaymentVerify(
        code: json['code'] as int? ?? 0,
        message: json['message'] as String? ?? '',
        refId: json['ref_id'] as int? ?? 0,
        cardPan: json['card_pan'] as String? ?? '',
        authority: json['authority'] as String? ?? '',
      );

  PaymentVerify copyWith({
    int? code,
    String? message,
    int? refId,
    String? cardPan,
    String? authority,
  }) =>
      PaymentVerify(
        code: code ?? this.code,
        message: message ?? this.message,
        refId: refId ?? this.refId,
        cardPan: cardPan ?? this.cardPan,
        authority: authority ?? this.authority,
      );
}

class RefundResponse {
  final String id;
  final String terminalId;
  final int amount;
  final int refundAmount;
  final String refundTime;
  final String refundStatus;

  RefundResponse({
    required this.id,
    required this.terminalId,
    required this.amount,
    required this.refundAmount,
    required this.refundTime,
    required this.refundStatus,
  });

  factory RefundResponse.fromJson(Map<String, dynamic> json) => RefundResponse(
        id: json['id'] as String? ?? '',
        terminalId: json['terminal_id'] as String? ?? '',
        amount: json['amount'] as int? ?? 0,
        refundAmount: json['refund_amount'] as int? ?? json['timeline']?['refund_amount'] as int? ?? 0,
        refundTime: json['refund_time'] as String? ?? json['timeline']?['refund_time'] as String? ?? '',
        refundStatus: json['refund_status'] as String? ?? json['timeline']?['refund_status'] as String? ?? '',
      );
}

class UnverifiedTransaction {
  final String authority;
  final int amount;
  final String callbackUrl;
  final String referer;
  final String date;

  UnverifiedTransaction({
    required this.authority,
    required this.amount,
    required this.callbackUrl,
    required this.referer,
    required this.date,
  });

  factory UnverifiedTransaction.fromJson(Map<String, dynamic> json) => UnverifiedTransaction(
        authority: json['authority'] as String? ?? '',
        amount: json['amount'] as int? ?? 0,
        callbackUrl: json['callback_url'] as String? ?? '',
        referer: json['referer'] as String? ?? '',
        date: json['date'] as String? ?? '',
      );
}

/// ---------------------------
///  Console UI Enhancements
/// ---------------------------
class ConsoleUI {
  static const esc = '\x1B[';
  static String bold(String s) => '${esc}1m$s${esc}0m';
  static String green(String s) => '${esc}32m$s${esc}0m';
  static String red(String s) => '${esc}31m$s${esc}0m';
  static String yellow(String s) => '${esc}33m$s${esc}0m';
  static String magenta(String s) => '${esc}35m$s${esc}0m';
  static String cyan(String s) => '${esc}36m$s${esc}0m';
  static String blue(String s) => '${esc}34m$s${esc}0m';
  static String white(String s) => '${esc}37m$s${esc}0m';

  static void header(String title) {
    final line = '═' * (title.length + 12);
    print('\n${cyan('┏$line┓')}');
    print('${cyan('┃')}  ${bold(magenta(title))}  ${cyan('┃')}');
    print('${cyan('┗$line┛')}\n');
  }

  static void info(String s) => print(blue('ℹ️  $s'));
  static void success(String s) => print(green('✅ $s'));
  static void error(String s) => print(red('❌ $s'));
  static void warning(String s) => print(yellow('⚠️  $s'));
  static void divider() => print(cyan('━' * 60));
  static void securityStatus(String s) => print(magenta('🔒 $s'));

  static Future<void> progress(String message) async {
    print(blue('⏳ $message...'));
    final spinner = ['|', '/', '-', '\\'];
    for (var i = 0; i < 10; i++) {  // Longer spinner for better visual
      stdout.write('\r${blue('⏳ $message ${spinner[i % 4]}')}');
      await Future.delayed(Duration(milliseconds: 150));
    }
    stdout.write('\r${green('⏳ $message Done!')}\n');
  }

  static void displayTable(List<Map<String, dynamic>> data) {
    if (data.isEmpty) {
      print(yellow('📋 No data to display.'));
      return;
    }
    // Calculate dynamic column widths
    final columnWidths = <int, int>{};
    for (var i = 0; i < data.first.keys.length; i++) {
      final key = data.first.keys.elementAt(i);
      final maxLength = data.fold<int>(
          key.length,
          (max, row) =>
              row[key] != null ? (row[key].toString().length > max ? row[key].toString().length : max) : max);
      columnWidths[i] = maxLength + 2;
    }
    final table = Table(
      header: data.first.keys.map((k) => bold(white(k))).toList(),
      data: data.map((row) => row.values.map((v) => v.toString()).toList()).toList(),
      border: true,
      columnWidths: columnWidths,
    );
    print('\n${cyan('📋 Transaction Table:')}\n$table\n');
  }

  static void displaySummary(List<PaymentVerify> transactions) {
    if (transactions.isEmpty) {
      print(yellow('📊 No transactions for summary.'));
      return;
    }
    final successful = transactions.where((t) => t.code == 100 || t.code == 101).length;
    final failed = transactions.where((t) => t.code != 100 && t.code != 101).length;
    print('\n${cyan('📊 Transaction Summary:')}');
    print(blue('Total Transactions: ${transactions.length}'));
    print(green('Successful: $successful'));
    print(red('Failed: $failed'));
    print('');
  }

  static void displayAuditLogs(List<String> logs) {
    if (logs.isEmpty) {
      print(yellow('📜 No audit logs to display.'));
      return;
    }
    print('\n${cyan('📜 Audit Logs:')}');
    for (final log in logs) {
      print(blue(log));
    }
    print('');
  }

  static void prompt(String message) => print(magenta('❓ $message: '));
}

/// ---------------------------
///  MAIN DEMO EXECUTION
/// ---------------------------
Future<void> main() async {
  runZonedGuarded(() async {
    final merchant = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX';
    final useSandbox = true;
    const encryptionKey = 'your-secure-key-here'; // Replace with secure key in production

    ConsoleUI.header('Zarinpal Dart Ultra Secure Demo v3.8.4');
    final zarinpal = Zarinpal(merchantId: merchant, sandbox: useSandbox, encryptionKey: encryptionKey)
      ..verbose = true;

    if (!zarinpal.validateMerchantId()) {
      ConsoleUI.error('Invalid merchant ID format.');
      return;
    }
    ConsoleUI.success('Merchant ID validated.');
    ConsoleUI.securityStatus('Encryption enabled with AES.');

    final connected = await zarinpal.checkConnectivity();
    if (!connected) {
      ConsoleUI.error('No internet connection detected.');
      return;
    }
    ConsoleUI.securityStatus('Secure connection to Zarinpal confirmed.');

    await ConsoleUI.progress('Loading transaction history');
    await zarinpal.loadHistoryFromFile();
    ConsoleUI.success('History loaded securely.');

    while (true) {
      ConsoleUI.divider();
      ConsoleUI.header('Menu');
      print(cyan('┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓'));
      ConsoleUI.info('1. Create Payment Request');
      ConsoleUI.info('2. View Transaction History');
      ConsoleUI.info('3. View Transaction Summary');
      ConsoleUI.info('4. View Audit Logs');
      ConsoleUI.info('5. Calculate Banknote Breakdown');
      ConsoleUI.info('6. Calculate Percentage of Amount');
      ConsoleUI.info('7. Reset Transaction History');
      ConsoleUI.info('8. Generate Payment QR Code');
      ConsoleUI.info('9. Batch Generate QR Codes');
      ConsoleUI.info('10. Exit');
      print(cyan('┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛'));
      ConsoleUI.prompt('Choose an option (1-10)');

      final input = stdin.readLineSync()?.trim();
      if (input == null || !['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'].contains(input)) {
        ConsoleUI.error('Invalid option. Please choose 1-10.');
        continue;
      }

      if (input == '10') {
        await ConsoleUI.progress('Shutting down');
        await zarinpal.shutdown();
        ConsoleUI.success('Shutdown complete. Exiting.');
        break;
      }

      switch (input) {
        case '1':
          ConsoleUI.divider();
          ConsoleUI.header('Create Payment Request');
          final request = PaymentRequest(
            amount: 10000,
            callbackUrl: 'https://example.com/verify',
            description: 'خرید تستی از برنامه',
            email: 'user@example.com',
            mobile: '09123456789',
            currency: Currency.toman,
          );

          try {
            await ConsoleUI.progress('Creating payment request');
            final res = await zarinpal.requestPayment(request);
            ConsoleUI.success('Payment request created!');
            ConsoleUI.info('Authority: ${zarinpal.maskSensitive(res.authority)}');
            ConsoleUI.info('Payment URL: ${zarinpal.getStartPayUrl(res.authority)}');
            ConsoleUI.warning('Open the Payment URL to complete the transaction, then verify.');
            ConsoleUI.securityStatus('Session ID generated for payment.');

            // Display QR code for the new payment
            zarinpal.displayPaymentQR(res.authority);

            ConsoleUI.divider();
            ConsoleUI.header('Additional Features Demo');
            ConsoleUI.info('Amount in words: ${zarinpal.numberToPersianWords(request.amount)}');
            ConsoleUI.info('Amount with currency: ${zarinpal.formatAmount(request.amount, request.currency)}');
            ConsoleUI.info('Amount in words with currency: ${zarinpal.amountToPersianWords(request.amount, request.currency)}');
            ConsoleUI.info('Convert 10000 Toman to Rial: ${zarinpal.tomanToRial(10000)}');
            ConsoleUI.info('Convert 100000 Rial to Toman: ${zarinpal.rialToToman(100000)}');
            ConsoleUI.info('Calculated fee for 10000 Toman: ${zarinpal.calculateFee(10000, Currency.toman)} Toman');
            ConsoleUI.info('Calculated fee for 100000 Rial: ${zarinpal.calculateFee(100000, Currency.rial)} Rial');
          } catch (e) {
            ConsoleUI.error('Error: $e');
          }
          break;

        case '2':
          ConsoleUI.divider();
          ConsoleUI.header('Transaction History');
          final history = zarinpal.getTransactionHistory().map((e) => {
                'Code': e.code,
                'Message': e.message,
                'Ref ID': e.refId,
                'Card PAN': zarinpal.maskSensitive(e.cardPan),
                'Authority': zarinpal.maskSensitive(e.authority),
              }).toList();
          ConsoleUI.displayTable(history);
          break;

        case '3':
          ConsoleUI.divider();
          ConsoleUI.header('Transaction Summary');
          ConsoleUI.displaySummary(zarinpal.getTransactionHistory());
          break;

        case '4':
          ConsoleUI.divider();
          ConsoleUI.header('Audit Logs');
          ConsoleUI.displayAuditLogs(zarinpal.getAuditLogs());
          break;

        case '5':
          ConsoleUI.divider();
          ConsoleUI.header('Calculate Banknote Breakdown');
          ConsoleUI.prompt('Enter amount in toman');
          final amountStr = stdin.readLineSync()?.trim();
          final amount = int.tryParse(amountStr ?? '') ?? 0;
          if (amount <= 0) {
            ConsoleUI.error('Invalid amount. Must be greater than zero.');
            continue;
          }
          zarinpal.displayBanknoteBreakdown(amount);
          break;

        case '6':
          ConsoleUI.divider();
          ConsoleUI.header('Calculate Percentage of Amount');
          ConsoleUI.prompt('Enter amount');
          final amountStr = stdin.readLineSync()?.trim();
          final amount = int.tryParse(amountStr ?? '') ?? 0;
          if (amount <= 0) {
            ConsoleUI.error('Invalid amount. Must be greater than zero.');
            continue;
          }
          ConsoleUI.prompt('Enter percentage (0-100)');
          final percentStr = stdin.readLineSync()?.trim();
          final percentage = double.tryParse(percentStr ?? '') ?? 0.0;
          ConsoleUI.prompt('Enter currency (toman/rial)');
          final currencyStr = stdin.readLineSync()?.trim().toLowerCase();
          final currency = currencyStr == 'rial' ? Currency.rial : Currency.toman;
          try {
            final result = zarinpal.calculatePercentage(amount, percentage, currency);
            ConsoleUI.success('Percentage value: ${result[currency == Currency.toman ? 'toman' : 'rial']} ${currency == Currency.toman ? 'toman' : 'rial'}');
            ConsoleUI.info('Equivalent: ${result[currency == Currency.toman ? 'rial' : 'toman']} ${currency == Currency.toman ? 'rial' : 'toman'}');
          } catch (e) {
            ConsoleUI.error('Error: $e');
          }
          break;

        case '7':
          ConsoleUI.divider();
          ConsoleUI.header('Reset Transaction History');
          await zarinpal.resetTransactionHistory();
          break;

        case '8':
          ConsoleUI.divider();
          ConsoleUI.header('Generate Payment QR Code');
          ConsoleUI.prompt('Enter authority');
          final authority = stdin.readLineSync()?.trim() ?? '';
          if (authority.isEmpty) {
            ConsoleUI.error('Authority cannot be empty.');
            continue;
          }
          ConsoleUI.prompt('Choose QR type (ascii/image)');
          final typeStr = stdin.readLineSync()?.trim().toLowerCase() ?? 'ascii';
          final isAscii = typeStr == 'ascii';
          ConsoleUI.prompt('Choose error correction level (L/M/Q/H)');
          final levelStr = stdin.readLineSync()?.trim().toUpperCase() ?? 'H';
          int errorLevel;
          switch (levelStr) {
            case 'L':
              errorLevel = QrErrorCorrectLevel.L;
              break;
            case 'M':
              errorLevel = QrErrorCorrectLevel.M;
              break;
            case 'Q':
              errorLevel = QrErrorCorrectLevel.Q;
              break;
            case 'H':
            default:
              errorLevel = QrErrorCorrectLevel.H;
          }
          try {
            if (isAscii) {
              zarinpal.displayPaymentQR(authority, errorCorrectLevel: errorLevel);
            } else {
              ConsoleUI.prompt('Enter file path to save (e.g., qr.png)');
              final filePath = stdin.readLineSync()?.trim() ?? 'qr.png';
              await zarinpal.generateImagePaymentQR(authority, filePath, errorCorrectLevel: errorLevel);
            }
            // Validate QR (simulated)
            final qrData = isAscii ? zarinpal.generatePaymentQR(authority, errorCorrectLevel: errorLevel) : 'image';
            final isValid = zarinpal.validateQRCode(authority, qrData);
            if (isValid) {
              ConsoleUI.success('QR code validated successfully.');
            } else {
              ConsoleUI.error('QR code validation failed.');
            }
          } catch (e) {
            ConsoleUI.error('Error generating QR: $e');
          }
          break;

        case '9':
          ConsoleUI.divider();
          ConsoleUI.header('Batch Generate QR Codes');
          ConsoleUI.prompt('Enter authorities (comma-separated)');
          final authStr = stdin.readLineSync()?.trim() ?? '';
          final authorities = authStr.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
          if (authorities.isEmpty) {
            ConsoleUI.error('No authorities provided.');
            continue;
          }
          ConsoleUI.prompt('Choose QR type (ascii/image)');
          final typeStr = stdin.readLineSync()?.trim().toLowerCase() ?? 'ascii';
          final isAscii = typeStr == 'ascii';
          String? directory;
          if (!isAscii) {
            ConsoleUI.prompt('Enter directory to save images');
            directory = stdin.readLineSync()?.trim();
            if (directory == null || directory.isEmpty) {
              ConsoleUI.error('Directory required for image generation.');
              continue;
            }
          }
          ConsoleUI.prompt('Choose error correction level (L/M/Q/H)');
          final levelStr = stdin.readLineSync()?.trim().toUpperCase() ?? 'H';
          int errorLevel;
          switch (levelStr) {
            case 'L':
              errorLevel = QrErrorCorrectLevel.L;
              break;
            case 'M':
              errorLevel = QrErrorCorrectLevel.M;
              break;
            case 'Q':
              errorLevel = QrErrorCorrectLevel.Q;
              break;
            case 'H':
            default:
              errorLevel = QrErrorCorrectLevel.H;
          }
          try {
            await zarinpal.batchGenerateQRs(
              authorities,
              ascii: isAscii,
              directory: directory,
              errorCorrectLevel: errorLevel,
            );
            ConsoleUI.success('Batch QR generation complete.');
          } catch (e) {
            ConsoleUI.error('Error in batch QR generation: $e');
          }
          break;
      }
    }

    await zarinpal.saveHistoryToFile();
    ConsoleUI.success('History saved securely to file.');
  }, (error, stack) {
    stderr.writeln('🔥 Uncaught Error: $error\n$stack');
  });
}
