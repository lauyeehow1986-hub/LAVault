package com.lavault.app_flutter

import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "com.lavault.app_flutter/paths"
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getAppSupportDir" -> {
                    val dir = applicationContext.filesDir
                    if (!dir.exists()) {
                        dir.mkdirs()
                    }
                    result.success(dir.absolutePath)
                }
                else -> result.notImplemented()
            }
        }
    }
}
