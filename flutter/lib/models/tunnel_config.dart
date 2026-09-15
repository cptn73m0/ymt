class TunnelConfig {
  final String server;
  final String port;
  final String clientId;
  final String key;
  final String domain;

  TunnelConfig({
    required this.server,
    required this.port,
    required this.clientId,
    required this.key,
    required this.domain,
  });

  factory TunnelConfig.fromYmtLink(String link) {
    if (!link.startsWith('ymt://')) {
      throw FormatException('Invalid YMT link');
    }
    // link format: ymt://base64EncryptedData
    // On the client side, we send the base64 data to server's decrypt endpoint
    return TunnelConfig(
      server: '',
      port: '',
      clientId: '',
      key: '',
      domain: '',
    );
  }

  Map<String, dynamic> toJson() => {
    'server': server,
    'port': port,
    'client_id': clientId,
    'key': key,
    'domain': domain,
  };

  factory TunnelConfig.fromJson(Map<String, dynamic> json) => TunnelConfig(
    server: json['server'] ?? '',
    port: json['port'] ?? '',
    clientId: json['client_id'] ?? '',
    key: json['key'] ?? '',
    domain: json['domain'] ?? '',
  );
}