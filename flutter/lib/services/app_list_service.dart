import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import '../models/app_info.dart';

class AppListService extends ChangeNotifier {
  static const _channel = MethodChannel('ymt/apps');

  Future<List<AppInfo>> getInstalledApps() async {
    try {
      if (Platform.isAndroid) {
        final list = await _channel.invokeMethod<List>('getInstalledApps');
        if (list != null) {
          return list.map((e) => AppInfo.fromJson(Map<String, dynamic>.from(e))).toList();
        }
      }
    } catch (e) {
      print('Get apps error: $e');
    }
    return [];
  }

  Future<void> saveSelection(List<AppInfo> apps) async {
    final selected = apps.where((a) => a.selected).map((a) => a.packageName).toList();
    try {
      if (Platform.isAndroid) {
        await _channel.invokeMethod('updateAllowedApps', {'apps': selected});
      }
    } catch (e) {
      print('Save selection error: $e');
    }
  }
}