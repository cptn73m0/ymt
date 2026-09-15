import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/tunnel_service.dart';

class HomeScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final tunnel = context.watch<TunnelService>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('YMT Client'),
        actions: [
          if (tunnel.isConfigured)
            IconButton(
              icon: Icon(tunnel.isRunning ? Icons.power_settings_new : Icons.power_settings_new),
              color: tunnel.isRunning ? Colors.green : Colors.grey,
              onPressed: () {
                if (tunnel.isRunning) {
                  tunnel.stop();
                } else {
                  tunnel.start([]);
                }
              },
            ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Status card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Column(
                  children: [
                    Icon(
                      tunnel.isRunning ? Icons.shield : Icons.shield_outlined,
                      size: 64,
                      color: tunnel.isRunning ? Colors.green : Colors.grey,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      tunnel.isRunning ? 'Connected' : 'Disconnected',
                      style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                    ),
                    if (tunnel.isConfigured) ...[
                      const SizedBox(height: 8),
                      Text(
                        tunnel.config?.clientId ?? '',
                        style: TextStyle(color: Colors.grey[400]),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Actions
            Row(
              children: [
                Expanded(
                  child: Card(
                    child: InkWell(
                      onTap: () => Navigator.pushNamed(context, '/add-config'),
                      borderRadius: BorderRadius.circular(12),
                      child: const Padding(
                        padding: EdgeInsets.all(16),
                        child: Column(
                          children: [
                            Icon(Icons.add_link, size: 32, color: Color(0xFF3B82F6)),
                            SizedBox(height: 8),
                            Text('Add Config', style: TextStyle(fontWeight: FontWeight.w600)),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Card(
                    child: InkWell(
                      onTap: () => Navigator.pushNamed(context, '/select-apps'),
                      borderRadius: BorderRadius.circular(12),
                      child: const Padding(
                        padding: EdgeInsets.all(16),
                        child: Column(
                          children: [
                            Icon(Icons.apps, size: 32, color: Color(0xFF3B82F6)),
                            SizedBox(height: 8),
                            Text('App Routing', style: TextStyle(fontWeight: FontWeight.w600)),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),

            const Spacer(),

            // Big connect button
            if (tunnel.isConfigured)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: () {
                    if (tunnel.isRunning) {
                      tunnel.stop();
                    } else {
                      tunnel.start([]);
                    }
                  },
                  icon: Icon(tunnel.isRunning ? Icons.power_settings_new : Icons.power_settings_new),
                  label: Text(tunnel.isRunning ? 'Disconnect' : 'Connect VPN',
                    style: const TextStyle(fontSize: 16)),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: tunnel.isRunning ? Colors.red : const Color(0xFF3B82F6),
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),

            if (!tunnel.isConfigured)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: () => Navigator.pushNamed(context, '/add-config'),
                  icon: const Icon(Icons.add_link),
                  label: const Text('Add Configuration', style: TextStyle(fontSize: 16)),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),

            const SizedBox(height: 16),

            // Config info
            if (tunnel.isConfigured)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          'Server: ${tunnel.config?.server ?? ""}\nDomain: ${tunnel.config?.domain ?? ""}',
                          style: TextStyle(color: Colors.grey[400], fontSize: 12),
                        ),
                      ),
                      TextButton(
                        onPressed: () {
                          tunnel.clearConfig();
                        },
                        child: const Text('Clear', style: TextStyle(color: Colors.red)),
                      ),
                    ],
                  ),
                ),
              ),

            const SizedBox(height: 8),
            Text(
              'v1.0.0',
              style: TextStyle(color: Colors.grey[600], fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }

  void _showAddDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Config'),
        content: const Text('Scan QR or paste ymt:// link'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
        ],
      ),
    );
  }
}