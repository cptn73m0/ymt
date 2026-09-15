package com.ymt.app

import android.app.Service
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import io.flutter.plugin.common.MethodChannel
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.Executors

class YMTVpnService : VpnService() {
    private var channel: ParcelFileDescriptor? = null
    private var running = false
    private var allowedApps = emptyList<String>()

    companion object {
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_NETMASK = "255.255.255.0"
        private const val VPN_DNS = "1.1.1.1"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val server = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val port = intent?.getStringExtra("port") ?: "9443"
        val key = intent?.getStringExtra("key") ?: ""
        val clientId = intent?.getStringExtra("client_id") ?: ""
        allowedApps = intent?.getStringArrayListExtra("allowed_apps") ?: arrayListOf()

        startVpn(clientId, key, server, port)
        return START_STICKY
    }

    private fun startVpn(clientId: String, key: String, server: String, port: String) {
        val builder = Builder()
        builder.setSession("YMT Tunnel")
        builder.setAddress(VPN_ADDRESS, 24)
        builder.addDnsServer(VPN_DNS)
        builder.setBlocking(true)

        // Per-app split tunneling
        if (allowedApps.isNotEmpty()) {
            for (app in allowedApps) {
                try {
                    builder.addAllowedApplication(app)
                } catch (e: PackageManager.NameNotFoundException) {
                    // Skip uninstalled apps
                }
            }
        }

        channel = builder.establish() ?: return
        running = true

        // Tunnel loop
        Executors.newSingleThreadExecutor().submit {
            val buf = ByteBuffer.allocate(32767)
            while (running) {
                val packet = channel?.readPacket(buf)
                // Forward through TLS/HTTP2 tunnel to server
                // (simplified - actual implementation uses Go library via gomobile)
            }
        }
    }

    override fun onDestroy() {
        running = false
        channel?.close()
        super.onDestroy()
    }
}