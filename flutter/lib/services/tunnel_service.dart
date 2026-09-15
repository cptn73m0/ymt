import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import '../models/tunnel_config.dart';

class TunnelService {
  static const _channel = MethodChannel('ymt/tunnel');

  TunnelConfig? _config;
  bool _isRunning = false;

  TunnelConfig? get config => _config;
  bool get isRunning => _isRunning;
  bool get isConfigured => _config != null;

  void setConfig(TunnelConfig config) {
    _config = config;
  }

  void clearConfig() {
    _config = null;
    _isRunning = false;
  }

  Future<TunnelConfig?> decryptLink(String link, String serverHost) async {
    try {
      final response = await http.post(
        Uri.parse('http://$serverHost/admin/api/decrypt-link'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'link': link}),
      );
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        _config = TunnelConfig.fromJson(data);
        return _config;
      }
    } catch (e) {
      print('Decrypt error: $e');
    }
    return null;
  }

  Future<bool> start(List<String> allowedApps) async {
    if (_config == null) return false;

    try {
      if (Platform.isAndroid) {
        final result = await _channel.invokeMethod<bool>('startVpn', {
          'server': _config!.server,
          'port': _config!.port,
          'client_id': _config!.clientId,
          'key': _config!.key,
          'allowed_apps': allowedApps,
        });
        _isRunning = result ?? false;
        return _isRunning;
      } else if (Platform.isWindows) {
        // Start ymt-client as subprocess
        final result = await Process.start(
          'ymt-client.exe',
          [
            '-server', '${_config!.server}:${_config!.port}',
            '-client-id', _config!.clientId,
            '-key', _config!.key,
            '-mode', 'socks5',
          ],
          runInShell: true,
        );
        _isRunning = true;
        return true;
      }
    } catch (e) {
      print('Start tunnel error: $e');
    }
    return false;
  }

  Future<void> stop() async {
    try {
      if (Platform.isAndroid) {
        await _channel.invokeMethod('stopVpn');
      } else if (Platform.isWindows) {
        await Process.run('taskkill', ['/f', '/im', 'ymt-client.exe'], runInShell: true);
      }
    } catch (e) {
      print('Stop error: $e');
    }
    _isRunning = false;
  }
}