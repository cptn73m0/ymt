import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/tunnel_service.dart';

class AddConfigScreen extends StatefulWidget {
  @override
  State<AddConfigScreen> createState() => _AddConfigScreenState();
}

class _AddConfigScreenState extends State<AddConfigScreen> {
  final _linkController = TextEditingController();
  final _serverController = TextEditingController(text: '2.27.123.198:8080');
  bool _loading = false;

  @override
  void dispose() {
    _linkController.dispose();
    _serverController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final tunnel = context.read<TunnelService>();

    return Scaffold(
      appBar: AppBar(title: const Text('Add Config')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
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
                        onPressed: _loading ? null : () async {
                          final link = _linkController.text.trim();
                          if (link.isEmpty) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(content: Text('Paste config link first')),
                            );
                            return;
                          }
                          setState(() => _loading = true);
                          try {
                            final cfg = await tunnel.decryptLink(link, _serverController.text.trim());
                            if (cfg != null && mounted) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Connected as ${cfg.clientId}')),
                              );
                              Navigator.pop(context);
                            } else if (mounted) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Failed to decrypt link. Check server address.')),
                              );
                            }
                          } catch (e) {
                            if (mounted) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Error: $e')),
                              );
                            }
                          } finally {
                            if (mounted) setState(() => _loading = false);
                          }
                        },
                        icon: _loading
                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                            : const Icon(Icons.check),
                        label: Text(_loading ? 'Decrypting...' : 'Apply'),
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
              'Server (for decryption)',
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