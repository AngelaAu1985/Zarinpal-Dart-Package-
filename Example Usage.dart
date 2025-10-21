import 'dart:convert';
import 'dart:io';
import 'package:zarinpal/zarinpal.dart'; // Hypothetical import for the Zarinpal SDK
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;

/// Enhanced professional usage of the Zarinpal Dart SDK for payment processing.
/// Features an interactive menu, dynamic configuration, robust error handling,
/// and extended utilities for a production-like environment.
Future<void> main() async {
  // Configuration defaults
  Map<String, dynamic> config = {
    'merchantId': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',
    'sandbox': true,
    'encryptionKey': 'your-secure-key-here-32-chars',
    'callbackPort': 8080,
    'logFile': 'zarinpal_audit.log',
  };

  // Load configuration from file if available
  try {
    final configFile = File('zarinpal_config.json');
    if (await configFile.exists()) {
      final configJson = await configFile.readAsString();
      config = jsonDecode(configJson) as Map<String, dynamic>;
      ConsoleUI.success('Configuration loaded from zarinpal_config.json');
    }
  } catch (e) {
    ConsoleUI.warning('Failed to load configuration file: $e');
  }

  // Initialize Zarinpal SDK
  final zarinpal = Zarinpal(
    merchantId: config['merchantId'] as String,
    sandbox: config['sandbox'] as bool,
    encryptionKey: config['encryptionKey'] as String,
  )..verbose = true;

  // Initialize audit log file
  final logFile = File(config['logFile'] as String);
  void logToFile(String message) async {
    await logFile.writeAsString(
      '[${DateTime.now().toIso8601String()}] $message\n',
      mode: FileMode.append,
    );
  }

  // Validate Merchant ID
  if (!zarinpal.validateMerchantId()) {
    ConsoleUI.error('Invalid Merchant ID. Please check your configuration.');
    logToFile('Invalid Merchant ID');
    exit(1);
  }
  ConsoleUI.success('Merchant ID validated successfully.');
  logToFile('Merchant ID validated');

  // Check connectivity to Zarinpal API
  if (!await zarinpal.checkConnectivity()) {
    ConsoleUI.error('Failed to connect to Zarinpal API. Check your network.');
    logToFile('Failed to connect to Zarinpal API');
    exit(1);
  }
  ConsoleUI.securityStatus('Secure connection to Zarinpal API established.');
  logToFile('Secure connection to Zarinpal API established');

  // Load transaction history
  await ConsoleUI.progress('Loading transaction history');
  try {
    await zarinpal.loadHistoryFromFile();
    ConsoleUI.success('Transaction history loaded securely.');
    logToFile('Transaction history loaded');
  } catch (e) {
    ConsoleUI.error('Failed to load transaction history: $e');
    logToFile('Failed to load transaction history: $e');
  }

  // Start callback server for payment verification
  HttpServer? server;
  try {
    server = await zarinpal.startCallbackServer(
      port: config['callbackPort'] as int,
      onVerified: (verify) {
        ConsoleUI.success('Payment verified! Ref ID: ${verify.refId}');
        ConsoleUI.info('Card PAN: ${zarinpal.maskSensitive(verify.cardPan)}');
        logToFile('Payment verified: Ref ID ${verify.refId}');
      },
      onFailed: (authority, status) {
        ConsoleUI.error('Payment failed for authority: $authority, Status: $status');
        logToFile('Payment failed: Authority $authority, Status $status');
      },
    );
    ConsoleUI.info('Callback server running at http://localhost:${config['callbackPort']}/verify');
    logToFile('Callback server started on port ${config['callbackPort']}');
  } catch (e) {
    ConsoleUI.error('Failed to start callback server: $e');
    logToFile('Failed to start callback server: $e');
    exit(1);
  }

  // Interactive menu loop
  while (true) {
    ConsoleUI.divider();
    ConsoleUI.header('Zarinpal Payment System');
    print(ConsoleUI.cyan('┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓'));
    ConsoleUI.info('1. Create Payment Request');
    ConsoleUI.info('2. View Transaction History');
    ConsoleUI.info('3. Generate Payment QR Code');
    ConsoleUI.info('4. Batch Generate QR Codes');
    ConsoleUI.info('5. Calculate Transaction Fee');
    ConsoleUI.info('6. Calculate Banknote Breakdown');
    ConsoleUI.info('7. View Audit Logs');
    ConsoleUI.info('8. Exit');
    print(ConsoleUI.cyan('┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛'));
    ConsoleUI.prompt('Select an option (1-8)');

    final input = stdin.readLineSync()?.trim();
    if (input == null || !['1', '2', '3', '4', '5', '6', '7', '8'].contains(input)) {
      ConsoleUI.error('Invalid option. Please select 1-8.');
      logToFile('Invalid menu option: $input');
      continue;
    }

    if (input == '8') {
      await ConsoleUI.progress('Shutting down');
      await zarinpal.saveHistoryToFile();
      await server.close(force: true);
      ConsoleUI.success('Application shutdown complete.');
      logToFile('Application shutdown');
      break;
    }

    switch (input) {
      case '1':
        ConsoleUI.divider();
        ConsoleUI.header('Create Payment Request');
        try {
          // Collect user input
          ConsoleUI.prompt('Enter amount (in Toman)');
          final amountStr = stdin.readLineSync()?.trim();
          final amount = int.tryParse(amountStr ?? '') ?? 0;
          if (amount <= 0) throw ArgumentError('Amount must be greater than zero.');

          ConsoleUI.prompt('Enter callback URL (e.g., http://localhost:8080/verify)');
          final callbackUrl = stdin.readLineSync()?.trim() ?? '';
          if (!Uri.parse(callbackUrl).isAbsolute) throw ArgumentError('Invalid callback URL.');

          ConsoleUI.prompt('Enter description');
          final description = stdin.readLineSync()?.trim() ?? '';
          if (description.isEmpty) throw ArgumentError('Description cannot be empty.');

          ConsoleUI.prompt('Enter email (optional, press Enter to skip)');
          final email = stdin.readLineSync()?.trim();
          ConsoleUI.prompt('Enter mobile (optional, press Enter to skip)');
          final mobile = stdin.readLineSync()?.trim();

          final paymentRequest = PaymentRequest(
            amount: amount,
            callbackUrl: callbackUrl,
            description: description,
            email: email?.isNotEmpty ?? false ? email : null,
            mobile: mobile?.isNotEmpty ?? false ? mobile : null,
            currency: Currency.toman,
          );

          await ConsoleUI.progress('Creating payment request');
          final paymentResponse = await zarinpal.requestPayment(paymentRequest);
          ConsoleUI.success('Payment request created successfully!');
          ConsoleUI.info('Authority: ${zarinpal.maskSensitive(paymentResponse.authority)}');
          final paymentUrl = zarinpal.getStartPayUrl(paymentResponse.authority);
          ConsoleUI.info('Payment URL: $paymentUrl');
          ConsoleUI.warning('Open the URL or scan the QR code to complete payment.');
          logToFile('Payment request created: Authority ${paymentResponse.authority}');

          // Display QR code
          ConsoleUI.header('Payment QR Code');
          zarinpal.displayPaymentQR(paymentResponse.authority);
        } catch (e) {
          ConsoleUI.error('Failed to create payment request: $e');
          logToFile('Failed to create payment request: $e');
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
        logToFile('Displayed transaction history');
        break;

      case '3':
        ConsoleUI.divider();
        ConsoleUI.header('Generate Payment QR Code');
        ConsoleUI.prompt('Enter authority');
        final authority = stdin.readLineSync()?.trim() ?? '';
        if (authority.isEmpty) {
          ConsoleUI.error('Authority cannot be empty.');
          logToFile('Empty authority for QR generation');
          continue;
        }
        ConsoleUI.prompt('Choose QR type (ascii/image)');
        final typeStr = stdin.readLineSync()?.trim().toLowerCase() ?? 'ascii';
        final isAscii = typeStr == 'ascii';
        try {
          if (isAscii) {
            zarinpal.displayPaymentQR(authority);
            logToFile('Generated ASCII QR for authority: $authority');
          } else {
            ConsoleUI.prompt('Enter file path to save (e.g., qr.png)');
            final filePath = stdin.readLineSync()?.trim() ?? 'qr.png';
            await zarinpal.generateImagePaymentQR(
              authority,
              filePath,
              scale: 6,
              fgColor: img.ColorRgb8(0, 0, 0),
              bgColor: img.ColorRgb8(255, 255, 255),
              quietZone: 4,
            );
            logToFile('Generated image QR for authority: $authority, saved to $filePath');
          }
          final qrData = isAscii ? zarinpal.generatePaymentQR(authority) : 'image';
          if (zarinpal.validateQRCode(authority, qrData)) {
            ConsoleUI.success('QR code validated successfully.');
            logToFile('QR code validated for authority: $authority');
          } else {
            ConsoleUI.error('QR code validation failed.');
            logToFile('QR code validation failed for authority: $authority');
          }
        } catch (e) {
          ConsoleUI.error('Error generating QR code: $e');
          logToFile('Error generating QR code: $e');
        }
        break;

      case '4':
        ConsoleUI.divider();
        ConsoleUI.header('Batch Generate QR Codes');
        ConsoleUI.prompt('Enter authorities (comma-separated)');
        final authStr = stdin.readLineSync()?.trim() ?? '';
        final authorities = authStr.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
        if (authorities.isEmpty) {
          ConsoleUI.error('No authorities provided.');
          logToFile('No authorities provided for batch QR generation');
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
            logToFile('Directory missing for batch QR generation');
            continue;
          }
        }
        try {
          await zarinpal.batchGenerateQRs(authorities, ascii: isAscii, directory: directory);
          ConsoleUI.success('Batch QR generation complete.');
          logToFile('Batch QR generation completed for ${authorities.length} authorities');
        } catch (e) {
          ConsoleUI.error('Error in batch QR generation: $e');
          logToFile('Error in batch QR generation: $e');
        }
        break;

      case '5':
        ConsoleUI.divider();
        ConsoleUI.header('Calculate Transaction Fee');
        ConsoleUI.prompt('Enter amount');
        final amountStr = stdin.readLineSync()?.trim();
        final amount = int.tryParse(amountStr ?? '') ?? 0;
        if (amount <= 0) {
          ConsoleUI.error('Invalid amount. Must be greater than zero.');
          logToFile('Invalid amount for fee calculation: $amountStr');
          continue;
        }
        ConsoleUI.prompt('Enter currency (toman/rial)');
        final currencyStr = stdin.readLineSync()?.trim().toLowerCase();
        final currency = currencyStr == 'rial' ? Currency.rial : Currency.toman;
        try {
          final fee = zarinpal.calculateFee(amount, currency);
          ConsoleUI.success('Transaction Fee: $fee ${currency == Currency.toman ? 'Toman' : 'Rial'}');
          logToFile('Calculated fee: $fee for $amount $currency');
        } catch (e) {
          ConsoleUI.error('Error calculating fee: $e');
          logToFile('Error calculating fee: $e');
        }
        break;

      case '6':
        ConsoleUI.divider();
        ConsoleUI.header('Calculate Banknote Breakdown');
        ConsoleUI.prompt('Enter amount in Toman');
        final amountStr = stdin.readLineSync()?.trim();
        final amount = int.tryParse(amountStr ?? '') ?? 0;
        if (amount <= 0) {
          ConsoleUI.error('Invalid amount. Must be greater than zero.');
          logToFile('Invalid amount for banknote breakdown: $amountStr');
          continue;
        }
        try {
          zarinpal.displayBanknoteBreakdown(amount);
          logToFile('Displayed banknote breakdown for $amount Toman');
        } catch (e) {
          ConsoleUI.error('Error calculating banknote breakdown: $e');
          logToFile('Error calculating banknote breakdown: $e');
        }
        break;

      case '7':
        ConsoleUI.divider();
        ConsoleUI.header('Audit Logs');
        ConsoleUI.displayAuditLogs(zarinpal.getAuditLogs());
        logToFile('Displayed audit logs');
        break;
    }
  }
}