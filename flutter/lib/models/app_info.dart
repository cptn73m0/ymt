class AppInfo {
  final String packageName;
  final String appName;
  bool selected;

  AppInfo({
    required this.packageName,
    required this.appName,
    this.selected = false,
  });

  Map<String, dynamic> toJson() => {
    'package_name': packageName,
    'app_name': appName,
    'selected': selected,
  };

  factory AppInfo.fromJson(Map<String, dynamic> json) => AppInfo(
    packageName: json['package_name'] ?? '',
    appName: json['app_name'] ?? '',
    selected: json['selected'] ?? false,
  );
}