import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';
import 'package:provider/provider.dart';
import 'services/tunnel_service.dart';
import 'services/app_list_service.dart';
import 'screens/home_screen.dart';
import 'screens/add_config_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();
  WindowOptions(
    size: Size(400, 600),
    center: true,
    title: 'YMT Client',
  ).then((_) => windowManager.waitUntilReadyToShow().then((_) {
    windowManager.show();
  }));

  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => TunnelService()),
        ChangeNotifierProvider(create: (_) => AppListService()),
      ],
      child: MaterialApp(
        title: 'YMT Client',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: const Color(0xFF0F0F12),
          colorScheme: ColorScheme.dark(
            primary: const Color(0xFF3B82F6),
            surface: const Color(0xFF1A1A24),
          ),
        ),
        home: HomeScreen(),
        routes: {
          '/add-config': (_) => AddConfigScreen(),
        },
      ),
    ),
  );
}