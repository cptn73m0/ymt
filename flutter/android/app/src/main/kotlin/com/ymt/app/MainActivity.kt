package com.ymt.app

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "ymt/tunnel"
    private val APPS_CHANNEL = "ymt/apps"
    private val VPN_REQUEST_CODE = 100

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        startActivityForResult(intent, VPN_REQUEST_CODE)
                        // Store params
                        result.success(true)
                    } else {
                        doStartVpn(call, result)
                    }
                }
                "stopVpn" -> {
                    stopService(Intent(this, YMTVpnService::class.java))
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, APPS_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "getInstalledApps" -> {
                    val apps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                    val list = apps.filter {
                        it.flags and ApplicationInfo.FLAG_SYSTEM == 0
                    }.map {
                        mapOf(
                            "package_name" to it.packageName,
                            "app_name" to packageManager.getApplicationLabel(it).toString(),
                            "selected" to false,
                        )
                    }
                    result.success(list)
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            // VPN prepared, start service
        }
    }

    private fun doStartVpn(call: io.flutter.plugin.common.MethodCall, result: MethodChannel.Result) {
        val intent = Intent(this, YMTVpnService::class.java).apply {
            putExtra("server", call.argument<String>("server"))
            putExtra("port", call.argument<String>("port"))
            putExtra("client_id", call.argument<String>("client_id"))
            putExtra("key", call.argument<String>("key"))
            putStringArrayListExtra("allowed_apps", call.argument<ArrayList<String>>("allowed_apps"))
        }
        startService(intent)
        result.success(true)
    }
}