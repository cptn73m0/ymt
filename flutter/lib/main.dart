import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/tunnel_service.dart';
import 'services/app_list_service.dart';
import 'screens/home_screen.dart';
import 'screens/add_config_screen.dart';
import 'screens/app_selection_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => TunnelService()),
        ChangeNotifierProvider(create: (_) => AppListService()),
      ],
      child: YMTApp(),
    ),
  );
}

class YMTApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'YMT Client',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0F0F12),
        colorScheme: ColorScheme.dark(
          primary: const Color(0xFF3B82F6),
          surface: const Color(0xFF1A1A24),
        ),
        cardTheme: CardThemeData(
          color: const Color(0xFF1A1A24),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
      initialRoute: '/',
      routes: {
        '/': (_) => HomeScreen(),
        '/add-config': (_) => AddConfigScreen(),
        '/select-apps': (_) => AppSelectionScreen(),
      },
    );
  }
}