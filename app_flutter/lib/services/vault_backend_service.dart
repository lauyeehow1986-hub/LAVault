import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:path_provider/path_provider.dart';

import '../src/rust/api.dart' as rust_api;
import '../src/rust/frb_generated.dart';
import '../src/rust/otp.dart';
import 'hardware_keystore_service.dart';

const MethodChannel _lavaultPathsChannel = MethodChannel(
  'com.lavault.app_flutter/paths',
);

/// Resolves a writable SQLite vault file path across Android, iOS, and Desktop.
///
/// On Android, prefers a native `MethodChannel` lookup (`Context.filesDir`) before
/// falling back across `path_provider` directories, ensuring parent directories exist
/// and throwing a diagnostic [StateError] rather than returning a relative filename.
Future<String> resolveVaultDbPath({
  String? dbPathOverride,
  bool? isAndroidOverride,
  Future<String?> Function()? nativeAndroidDirProvider,
  Future<Directory> Function()? supportDirProvider,
  Future<Directory> Function()? docsDirProvider,
  Future<Directory> Function()? tempDirProvider,
}) async {
  if (dbPathOverride != null && dbPathOverride.trim().isNotEmpty) {
    return dbPathOverride;
  }

  final isAndroid = isAndroidOverride ?? (!kIsWeb && Platform.isAndroid);
  final errors = <String>[];

  Future<String?> tryDir(
    String label,
    Future<String?> Function() getter,
  ) async {
    try {
      final rawPath = await getter();
      final dirPath = rawPath?.trim();
      if (dirPath == null || dirPath.isEmpty) {
        errors.add('$label: returned empty path');
        return null;
      }
      await Directory(dirPath).create(recursive: true);
      final normalized = dirPath.endsWith('/') || dirPath.endsWith('\\')
          ? dirPath.substring(0, dirPath.length - 1)
          : dirPath;
      return '$normalized/lavault_mobile.db';
    } catch (e) {
      errors.add('$label: $e');
      return null;
    }
  }

  if (isAndroid) {
    final nativePath = await tryDir(
      'nativeAndroid',
      nativeAndroidDirProvider ??
          () => _lavaultPathsChannel.invokeMethod<String>('getAppSupportDir'),
    );
    if (nativePath != null) return nativePath;
  }

  final supportPath = await tryDir(
    'appSupport',
    () async => (await (supportDirProvider ?? getApplicationSupportDirectory)()).path,
  );
  if (supportPath != null) return supportPath;

  final docsPath = await tryDir(
    'appDocs',
    () async => (await (docsDirProvider ?? getApplicationDocumentsDirectory)()).path,
  );
  if (docsPath != null) return docsPath;

  final tempPath = await tryDir(
    'tempDir',
    () async => (await (tempDirProvider ?? getTemporaryDirectory)()).path,
  );
  if (tempPath != null) return tempPath;

  if (isAndroid) {
    throw StateError(
      'Unable to resolve writable Android storage directory (${errors.join('; ')})',
    );
  }

  try {
    final sysTemp = Directory.systemTemp;
    await sysTemp.create(recursive: true);
    return '${sysTemp.path}/lavault_mobile.db';
  } catch (_) {
    return 'lavault_mobile.db';
  }
}

class PendingUnlockRequest {
  final String id;
  final String channel; // 'Wi-Fi TLS 1.3' | 'BLE GATT' | 'Optical QR'
  final String requesterName;
  final String targetFile;
  final String slotType; // '1-of-N Direct' | 'K-of-N Quorum (2-of-3)'
  final String? urRequestPayload;
  final String? callbackUrl;
  String status; // 'Pending' | 'Approved' | 'Denied'
  String? urResponsePayload;

  PendingUnlockRequest({
    required this.id,
    required this.channel,
    required this.requesterName,
    required this.targetFile,
    required this.slotType,
    this.urRequestPayload,
    this.callbackUrl,
    this.status = 'Pending',
    this.urResponsePayload,
  });
}

class AuthorizedPeer {
  final String id;
  final String x25519Hex;
  final String transport;

  const AuthorizedPeer({
    required this.id,
    required this.x25519Hex,
    required this.transport,
  });
}

abstract class VaultBackendApi {
  Future<void> ensureInitialized();
  Future<rust_api.SessionInfoDto> createOrUnlockVault({
    required String dbPath,
    required String masterPassword,
    required List<int> hardwareSecret,
  });
  Future<void> lockSession({required String sessionId});
  Future<String> addVaultEntry({
    required String sessionId,
    required rust_api.VaultEntryInputDto entry,
  });
  Future<List<rust_api.VaultEntrySummaryDto>> listVaultEntries({
    required String sessionId,
  });
  Future<List<rust_api.VaultEntrySummaryDto>> searchVaultEntries({
    required String sessionId,
    required String query,
  });
  Future<rust_api.UnlockedVaultEntryDto> unlockVaultEntryAt({
    required String sessionId,
    required String entryId,
    required BigInt unixTime,
  });
  Future<String> approveBcurUnlockRequest({
    required String sessionId,
    required String urReq,
  });
  Future<rust_api.RecoveryKitDto> exportRecoveryKit({
    required String sessionId,
    required String rkfPassword,
    required List<String> guardianIds,
    required int thresholdK,
  });
  Future<rust_api.TransportConfigDto> getTransportConfig();
  Future<rust_api.VltInspectDto> inspectVltFile({required String path});
  Future<void> deleteVaultEntry({
    required String sessionId,
    required String entryId,
  });
}

class RustVaultBackendApi implements VaultBackendApi {
  bool _initialized = false;

  static ExternalLibrary? _resolveExternalLibrary() {
    if (kIsWeb) return null;
    if (Platform.isAndroid) {
      return ExternalLibrary.open('libvault_core.so');
    } else if (Platform.isWindows) {
      final candidates = [
        'vault_core.dll',
        '../target/release/vault_core.dll',
        '../target/debug/vault_core.dll',
        '${File(Platform.resolvedExecutable).parent.path}/vault_core.dll',
      ];
      for (final c in candidates) {
        if (File(c).existsSync()) {
          return ExternalLibrary.open(c);
        }
      }
    } else if (Platform.isLinux) {
      for (final c in [
        'libvault_core.so',
        '../target/release/libvault_core.so',
        '../target/debug/libvault_core.so',
      ]) {
        if (File(c).existsSync()) return ExternalLibrary.open(c);
      }
    } else if (Platform.isMacOS) {
      for (final c in [
        'libvault_core.dylib',
        '../target/release/libvault_core.dylib',
        '../target/debug/libvault_core.dylib',
      ]) {
        if (File(c).existsSync()) return ExternalLibrary.open(c);
      }
    }
    return null;
  }

  @override
  Future<void> ensureInitialized() async {
    if (_initialized) return;
    await RustLib.init(externalLibrary: _resolveExternalLibrary());
    _initialized = true;
  }

  @override
  Future<rust_api.SessionInfoDto> createOrUnlockVault({
    required String dbPath,
    required String masterPassword,
    required List<int> hardwareSecret,
  }) =>
      rust_api.createIdentityAndVault(
        dbPath: dbPath,
        masterPassword: masterPassword,
        hardwareSecret: hardwareSecret,
      );

  @override
  Future<void> lockSession({required String sessionId}) =>
      rust_api.lockSession(sessionId: sessionId);

  @override
  Future<String> addVaultEntry({
    required String sessionId,
    required rust_api.VaultEntryInputDto entry,
  }) =>
      rust_api.addVaultEntry(sessionId: sessionId, entry: entry);

  @override
  Future<List<rust_api.VaultEntrySummaryDto>> listVaultEntries({
    required String sessionId,
  }) =>
      rust_api.listVaultEntries(sessionId: sessionId);

  @override
  Future<List<rust_api.VaultEntrySummaryDto>> searchVaultEntries({
    required String sessionId,
    required String query,
  }) =>
      rust_api.searchVaultEntries(sessionId: sessionId, query: query);

  @override
  Future<rust_api.UnlockedVaultEntryDto> unlockVaultEntryAt({
    required String sessionId,
    required String entryId,
    required BigInt unixTime,
  }) =>
      rust_api.unlockVaultEntryAt(
        sessionId: sessionId,
        entryId: entryId,
        unixTime: unixTime,
      );

  @override
  Future<void> deleteVaultEntry({
    required String sessionId,
    required String entryId,
  }) =>
      rust_api.deleteVaultEntry(sessionId: sessionId, entryId: entryId);

  @override
  Future<String> approveBcurUnlockRequest({
    required String sessionId,
    required String urReq,
  }) =>
      rust_api.approveBcurUnlockRequest(sessionId: sessionId, urReq: urReq);

  @override
  Future<rust_api.RecoveryKitDto> exportRecoveryKit({
    required String sessionId,
    required String rkfPassword,
    required List<String> guardianIds,
    required int thresholdK,
  }) =>
      rust_api.exportRecoveryKit(
        sessionId: sessionId,
        rkfPassword: rkfPassword,
        guardianIds: guardianIds,
        thresholdK: thresholdK,
      );

  @override
  Future<rust_api.TransportConfigDto> getTransportConfig() =>
      rust_api.getTransportConfig();

  @override
  Future<rust_api.VltInspectDto> inspectVltFile({required String path}) =>
      rust_api.inspectVltFile(path: path);
}

class VaultController extends ChangeNotifier {
  final VaultBackendApi api;
  final VaultKeystoreBackend keystore;
  final String? dbPathOverride;

  rust_api.SessionInfoDto? session;
  rust_api.TransportConfigDto? transportConfig;
  List<rust_api.VaultEntrySummaryDto> entries = [];
  final Map<String, rust_api.UnlockedVaultEntryDto> unlockedCache = {};
  final List<PendingUnlockRequest> unlockQueue = [
    PendingUnlockRequest(
      id: 'req_wifi_01',
      channel: 'Wi-Fi TLS 1.3',
      requesterName: 'Workstation-Win11',
      targetFile: 'payroll_2026.vlt',
      slotType: '1-of-N Direct',
    ),
    PendingUnlockRequest(
      id: 'req_ble_02',
      channel: 'BLE GATT',
      requesterName: 'ThinkPad-Linux',
      targetFile: 'Virtual Drive Z:\\',
      slotType: 'K-of-N Quorum (2-of-3)',
    ),
  ];
  final List<AuthorizedPeer> peers = [];
  int quorumThresholdK = 2;
  final List<String> guardianIds = [
    'guardian_alice',
    'guardian_bob',
    'guardian_charlie',
  ];
  rust_api.RecoveryKitDto? recoveryKit;
  String? lastError;
  String lastWifiHost = '';
  String? wifiStatus;
  Timer? _totpTicker;

  VaultController({
    VaultBackendApi? api,
    VaultKeystoreBackend? keystore,
    this.dbPathOverride,
  })  : api = api ?? RustVaultBackendApi(),
        keystore = keystore ?? HardwareKeystoreService();

  bool get isUnlocked => session != null;

  Future<void> unlockWithMasterPassword(String masterPassword) async {
    lastError = null;
    try {
      final bioOk = await keystore.authenticateWithBiometrics(
        reason: 'Authenticate to unwrap LaVault MasterIdentitySeed',
      );
      if (!bioOk) {
        lastError = 'Biometric authentication cancelled';
        notifyListeners();
        return;
      }

      await api.ensureInitialized();
      final hwSecret = await keystore.getOrCreateHardwareSecret();
      final dbPath = await resolveVaultDbPath(dbPathOverride: dbPathOverride);

      session = await api.createOrUnlockVault(
        dbPath: dbPath,
        masterPassword: masterPassword,
        hardwareSecret: hwSecret,
      );
      transportConfig = await api.getTransportConfig();

      if (peers.isEmpty && session != null) {
        peers.add(
          AuthorizedPeer(
            id: 'this_device',
            x25519Hex: session!.x25519PublicHex,
            transport: 'Local Keystore',
          ),
        );
      }

      entries = await api.listVaultEntries(sessionId: session!.sessionId);
      if (entries.isEmpty) {
        await addCredential(
          title: 'GitHub Work',
          username: 'dev@lavault.local',
          password: 'Tr0ub4dor&3-LaVault!',
          totpSecretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          digits: 8,
          algorithm: OtpAlgorithm.sha1,
        );
      }

      _totpTicker?.cancel();
      _totpTicker = Timer.periodic(
        const Duration(seconds: 1),
        (_) => refreshUnlockedTotps(),
      );
      notifyListeners();
    } catch (e) {
      lastError = e.toString();
      notifyListeners();
    }
  }

  Future<void> lockVault() async {
    _totpTicker?.cancel();
    _totpTicker = null;
    if (session != null) {
      await api.lockSession(sessionId: session!.sessionId);
    }
    session = null;
    entries = [];
    unlockedCache.clear();
    recoveryKit = null;
    notifyListeners();
  }

  Future<void> addCredential({
    required String title,
    required String username,
    required String password,
    String? totpSecretBase32,
    OtpAlgorithm algorithm = OtpAlgorithm.sha1,
    int digits = 6,
  }) async {
    if (session == null) return;
    await api.addVaultEntry(
      sessionId: session!.sessionId,
      entry: rust_api.VaultEntryInputDto(
        title: title,
        username: username,
        password: password,
        totpSecretBase32:
            totpSecretBase32?.trim().isEmpty == true ? null : totpSecretBase32,
        totpAlgorithm: algorithm,
        totpDigits: digits,
        totpPeriodSecs: BigInt.from(30),
        url: null,
        notes: null,
      ),
    );
    entries = await api.listVaultEntries(sessionId: session!.sessionId);
    notifyListeners();
  }

  Future<void> deleteCredential(String entryId) async {
    if (session == null) return;
    unlockedCache.remove(entryId);
    await api.deleteVaultEntry(
      sessionId: session!.sessionId,
      entryId: entryId,
    );
    entries = await api.listVaultEntries(sessionId: session!.sessionId);
    notifyListeners();
  }

  Future<void> search(String query) async {
    if (session == null) return;
    entries = query.trim().isEmpty
        ? await api.listVaultEntries(sessionId: session!.sessionId)
        : await api.searchVaultEntries(
            sessionId: session!.sessionId,
            query: query,
          );
    notifyListeners();
  }

  Future<void> toggleRevealEntry(String entryId) async {
    if (session == null) return;
    if (unlockedCache.containsKey(entryId)) {
      unlockedCache.remove(entryId);
      notifyListeners();
      return;
    }
    final nowSec = BigInt.from(DateTime.now().millisecondsSinceEpoch ~/ 1000);
    unlockedCache[entryId] = await api.unlockVaultEntryAt(
      sessionId: session!.sessionId,
      entryId: entryId,
      unixTime: nowSec,
    );
    notifyListeners();
  }

  Future<void> refreshUnlockedTotps() async {
    if (session == null || unlockedCache.isEmpty) return;
    final nowSec = BigInt.from(DateTime.now().millisecondsSinceEpoch ~/ 1000);
    for (final id in unlockedCache.keys.toList()) {
      unlockedCache[id] = await api.unlockVaultEntryAt(
        sessionId: session!.sessionId,
        entryId: id,
        unixTime: nowSec,
      );
    }
    notifyListeners();
  }

  Future<String?> processBcurRequest(String urReq) async {
    if (session == null) return null;
    final urRes = await api.approveBcurUnlockRequest(
      sessionId: session!.sessionId,
      urReq: urReq.trim(),
    );
    unlockQueue.insert(
      0,
      PendingUnlockRequest(
        id: 'qr_${DateTime.now().millisecondsSinceEpoch}',
        channel: 'Optical QR (bc-ur)',
        requesterName: 'Air-Gapped PC',
        targetFile: 'ur:lavault-req',
        slotType: '1-of-N Direct',
        urRequestPayload: urReq.trim(),
        status: 'Approved',
        urResponsePayload: urRes,
      ),
    );
    notifyListeners();
    return urRes;
  }

  String normalizeWifiBaseUrl(String raw) {
    var s = raw.trim();
    if (s.toLowerCase().startsWith('lavault-wifi://')) {
      s = s.substring('lavault-wifi://'.length);
    }
    if (!s.startsWith('http://') && !s.startsWith('https://')) {
      s = 'http://$s';
    }
    final uri = Uri.parse(s);
    final port = uri.hasPort ? uri.port : 53319;
    return '${uri.scheme}://${uri.host}:$port';
  }

  Future<bool> fetchPendingWifiUnlock(String hostOrUrl) async {
    final baseUrl = normalizeWifiBaseUrl(hostOrUrl);
    lastWifiHost = baseUrl.replaceFirst('http://', '');
    wifiStatus = 'Checking $lastWifiHost...';
    notifyListeners();

    final client = HttpClient()..connectionTimeout = const Duration(seconds: 5);
    try {
      final req = await client.getUrl(Uri.parse('$baseUrl/pending'));
      final res = await req.close();
      final body = await utf8.decodeStream(res);
      if (res.statusCode != 200) {
        wifiStatus = 'Wi-Fi error (${res.statusCode}): $body';
        notifyListeners();
        return false;
      }
      final map = jsonDecode(body) as Map<String, dynamic>;
      final reqId = (map['req_id'] ?? '').toString();
      final requester = (map['requester_name'] ?? 'LaVault-PC').toString();
      final targetFile = (map['target_file'] ?? 'file.vlt').toString();
      final urReq = (map['ur_req'] ?? '').toString();
      if (reqId.isEmpty || urReq.isEmpty) {
        wifiStatus = 'Wi-Fi error: invalid challenge JSON from PC';
        notifyListeners();
        return false;
      }

      unlockQueue.removeWhere((item) => item.id == reqId);
      unlockQueue.insert(
        0,
        PendingUnlockRequest(
          id: reqId,
          channel: 'Wi-Fi LAN (E2EE)',
          requesterName: requester,
          targetFile: targetFile,
          slotType: '1-of-N Direct (Live Wi-Fi)',
          urRequestPayload: urReq,
          callbackUrl: baseUrl,
        ),
      );
      wifiStatus = 'Ready: tap Approve Unlock below to unlock $targetFile';
      notifyListeners();
      return true;
    } catch (e) {
      wifiStatus = 'Wi-Fi error: $e';
      notifyListeners();
      return false;
    } finally {
      client.close(force: true);
    }
  }

  Future<void> respondToQueueItem(String id, bool approve) async {
    final idx = unlockQueue.indexWhere((r) => r.id == id);
    if (idx == -1) return;
    final item = unlockQueue[idx];

    if (item.callbackUrl != null && item.urRequestPayload != null) {
      final client = HttpClient()..connectionTimeout = const Duration(seconds: 5);
      try {
        if (approve) {
          if (session == null) {
            wifiStatus = 'Unlock the app vault first';
            notifyListeners();
            return;
          }
          final urRes = await api.approveBcurUnlockRequest(
            sessionId: session!.sessionId,
            urReq: item.urRequestPayload!,
          );
          final httpReq = await client.postUrl(
            Uri.parse('${item.callbackUrl}/respond'),
          );
          httpReq.headers.contentType = ContentType.text;
          httpReq.write(urRes);
          final httpRes = await httpReq.close();
          final body = await utf8.decodeStream(httpRes);
          if (httpRes.statusCode != 200) {
            wifiStatus = 'PC rejected unlock (${httpRes.statusCode}): $body';
            notifyListeners();
            return;
          }
          item.status = 'Approved (Sent to PC)';
          item.urResponsePayload = urRes;
          wifiStatus = 'Approved & sent to PC!';
        } else {
          final httpReq = await client.postUrl(
            Uri.parse('${item.callbackUrl}/deny'),
          );
          await httpReq.close();
          item.status = 'Denied';
          wifiStatus = 'Unlock request denied';
        }
      } catch (e) {
        wifiStatus = 'Wi-Fi send error: $e';
      } finally {
        client.close(force: true);
      }
      notifyListeners();
      return;
    }

    item.status = approve ? 'Approved' : 'Denied';
    notifyListeners();
  }

  void addAuthorizedPeer(String id, String x25519Hex, String transport) {
    peers.add(AuthorizedPeer(
      id: id,
      x25519Hex: x25519Hex,
      transport: transport,
    ));
    notifyListeners();
  }

  void removeAuthorizedPeer(String id) {
    peers.removeWhere((p) => p.id == id);
    notifyListeners();
  }

  Future<void> generateRecoveryKit(String rkfPassword) async {
    if (session == null) return;
    recoveryKit = await api.exportRecoveryKit(
      sessionId: session!.sessionId,
      rkfPassword: rkfPassword,
      guardianIds: guardianIds,
      thresholdK: quorumThresholdK,
    );
    notifyListeners();
  }

  @override
  void dispose() {
    _totpTicker?.cancel();
    super.dispose();
  }
}
