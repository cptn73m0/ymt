import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/app_list_service.dart';
import '../models/app_info.dart';

class AppSelectionScreen extends StatefulWidget {
  @override
  State<AppSelectionScreen> createState() => _AppSelectionScreenState();
}

class _AppSelectionScreenState extends State<AppSelectionScreen> {
  List<AppInfo> _apps = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadApps();
  }

  Future<void> _loadApps() async {
    final service = context.read<AppListService>();
    final apps = await service.getInstalledApps();
    setState(() {
      _apps = apps;
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('App Routing'),
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: () {},
          ),
        ],
      ),
      body: Column(
        children: [
          // Info banner
          Container(
            padding: const EdgeInsets.all(12),
            margin: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1A1A24),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Row(
              children: [
                Icon(Icons.info_outline, color: Color(0xFF3B82F6), size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Selected apps route through tunnel. Unselected go directly.',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                ),
              ],
            ),
          ),

          // Apps list
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _apps.isEmpty
                    ? const Center(child: Text('No apps found'))
                    : RefreshIndicator(
                        onRefresh: _loadApps,
                        child: ListView.builder(
                          itemCount: _apps.length,
                          itemBuilder: (ctx, i) {
                            final app = _apps[i];
                            return ListTile(
                              leading: const Icon(Icons.app_shortcut),
                              title: Text(app.appName),
                              subtitle: Text(app.packageName, style: TextStyle(fontSize: 11, color: Colors.grey[500])),
                              trailing: Checkbox(
                                value: app.selected,
                                onChanged: (v) {
                                  setState(() => app.selected = v ?? false);
                                },
                              ),
                            );
                          },
                        ),
                      ),
          ),
        ],
      ),
      bottomNavigationBar: Padding(
        padding: const EdgeInsets.all(16),
        child: SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: () {
              context.read<AppListService>().saveSelection(_apps);
              Navigator.pop(context);
            },
            child: const Text('Save Selection'),
          ),
        ),
      ),
    );
  }
}