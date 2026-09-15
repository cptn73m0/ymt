import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/tunnel_service.dart';

class AddConfigScreen extends StatelessWidget {
  final _linkController = TextEditingController();
  final _serverController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    final tunnel = context.read<TunnelService>();

    return Scaffold(
      appBar: AppBar(title: const Text('Add Config')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Manual entry
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Paste ymt:// link', style: TextStyle(fontWeight: FontWeight.w600)),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _linkController,
                      decoration: const InputDecoration(
                        hintText: 'ymt://...',
                        border: OutlineInputBorder(),
                      ),
                      maxLines: 3,
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () async {
                          final link = _linkController.text.trim();
                          if (link.isEmpty) return;
                          final cfg = await tunnel.decryptLink(link, _serverController.text.trim());
                          if (cfg != null && context.mounted) {
                            Navigator.pop(context);
                          }
                        },
                        icon: const Icon(Icons.check),
                        label: const Text('Apply'),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Scan QR
            Card(
              child: InkWell(
                onTap: () {
                  // TODO: open QR scanner
                },
                borderRadius: BorderRadius.circular(12),
                child: const Padding(
                  padding: EdgeInsets.all(20),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.qr_code_scanner, size: 32, color: Color(0xFF3B82F6)),
                      SizedBox(width: 12),
                      Text('Scan QR Code', style: TextStyle(fontSize: 16)),
                    ],
                  ),
                ),
              ),
            ),

            const SizedBox(height: 16),
            Text(
              'Server IP (for decryption)',
              style: TextStyle(color: Colors.grey[400]),
            ),
            TextField(
              controller: _serverController,
              decoration: const InputDecoration(
                hintText: '2.27.123.198:8080',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
      ),
    );
  }
}