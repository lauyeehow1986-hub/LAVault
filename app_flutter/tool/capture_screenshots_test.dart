import 'dart:io';
import 'dart:ui' as ui;

import 'package:app_flutter/main.dart';
import 'package:app_flutter/services/hardware_keystore_service.dart';
import 'package:app_flutter/services/vault_backend_service.dart';
import 'package:app_flutter/src/rust/api.dart' as rust_api;
import 'package:app_flutter/src/rust/otp.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class DemoKeystore implements VaultKeystoreBackend {
  @override
  Future<bool> authenticateWithBiometrics({required String reason}) async => true;

  @override
  Future<List<int>> getOrCreateHardwareSecret() async => List<int>.filled(32, 0x42);
}

class DemoBackendApi implements VaultBackendApi {
  final List<rust_api.VaultEntryInputDto> _stored = [];

  static const _demoTotpCodes = <String, (String, int)>{
    'GitHub Work': ('94287082', 19),
    'Cloudflare Prod': ('482913', 14),
    'AWS Root Vault': ('731049', 22),
  };

  @override
  Future<void> ensureInitialized() async {}

  @override
  Future<rust_api.SessionInfoDto> createOrUnlockVault({
    required String dbPath,
    required String masterPassword,
    required List<int> hardwareSecret,
  }) async {
    return rust_api.SessionInfoDto(
      sessionId: 'sess_demo_01',
      x25519PublicBytes: Uint8List(32),
      ed25519PublicBytes: Uint8List(32),
      x25519PublicHex:
          '4e8a9c12b73f01d4567e89ab0123cd45ef67890123456789abcdef0123456789'
              .substring(0, 64),
      ed25519PublicHex:
          '9f12c3d4e5a6b7890123456789abcdef0123456789abcdef1122334455667788',
    );
  }

  @override
  Future<void> lockSession({required String sessionId}) async {}

  @override
  Future<String> addVaultEntry({
    required String sessionId,
    required rust_api.VaultEntryInputDto entry,
  }) async {
    _stored.add(entry);
    return 'entry_${_stored.length}';
  }

  @override
  Future<List<rust_api.VaultEntrySummaryDto>> listVaultEntries({
    required String sessionId,
  }) async {
    return [
      for (var i = 0; i < _stored.length; i++)
        rust_api.VaultEntrySummaryDto(
          id: 'entry_${i + 1}',
          title: _stored[i].title,
          username: _stored[i].username,
          hasTotp: _stored[i].totpSecretBase32 != null,
          url: _stored[i].url,
          updatedAt: 1700000000,
        ),
    ];
  }

  @override
  Future<List<rust_api.VaultEntrySummaryDto>> searchVaultEntries({
    required String sessionId,
    required String query,
  }) async {
    final all = await listVaultEntries(sessionId: sessionId);
    return all
        .where((e) => e.title.toLowerCase().contains(query.toLowerCase()))
        .toList();
  }

  @override
  Future<rust_api.UnlockedVaultEntryDto> unlockVaultEntryAt({
    required String sessionId,
    required String entryId,
    required BigInt unixTime,
  }) async {
    final idx = int.parse(entryId.split('_').last) - 1;
    final e = _stored[idx];
    final totpInfo = _demoTotpCodes[e.title] ?? ('654321', 21);
    return rust_api.UnlockedVaultEntryDto(
      id: entryId,
      title: e.title,
      username: e.username,
      password: e.password,
      totpCode: totpInfo.$1,
      totpRemainingSecs: BigInt.from(totpInfo.$2),
      url: e.url,
      notes: e.notes,
    );
  }

  @override
  Future<void> deleteVaultEntry({
    required String sessionId,
    required String entryId,
  }) async {
    final idx = int.parse(entryId.split('_').last) - 1;
    if (idx >= 0 && idx < _stored.length) {
      _stored.removeAt(idx);
    }
  }

  @override
  Future<String> approveBcurUnlockRequest({
    required String sessionId,
    required String urReq,
  }) async {
    return 'ur:lavault-res/oeadbaecgdjkfhlmnpqrstuvwxzy0123456789abcdefaeghijklmnpqrstuvwxyzaecdbaecgdjkfhlmnpqrst';
  }

  @override
  Future<rust_api.RecoveryKitDto> exportRecoveryKit({
    required String sessionId,
    required String rkfPassword,
    required List<String> guardianIds,
    required int thresholdK,
  }) async {
    const words =
        'abandon ability able about above absent absorb abstract absurd abuse access accident '
        'account accuse achieve acid acoustic acquire across act action actor actress actual';
    const sampleShares = <String>[
      'lavault-share://v1/2-of-3/idx-1/7f9e1a2b3c4d5e6f00112233445566778899aabbccddeeff.9c12a4b0',
      'lavault-share://v1/2-of-3/idx-2/3b4c5d6e7f8091a2bbccddeeff00112233445566778899aa.5e7d21f4',
      'lavault-share://v1/2-of-3/idx-3/e1d2c3b4a5968778695a4b3c2d1e0f102030405060708090.1a8c33d9',
    ];
    return rust_api.RecoveryKitDto(
      bip3924Words: words,
      rkfBytes: Uint8List.fromList(List<int>.generate(112, (i) => (i * 17) & 0xff)),
      guardianCapsules: [
        for (var i = 0; i < guardianIds.length; i++)
          rust_api.GuardianCapsuleDto(
            guardianId: guardianIds[i],
            shareIndex: i + 1,
            thresholdK: thresholdK,
            totalN: guardianIds.length,
            slip39Uri: sampleShares[i % sampleShares.length],
            signatureHex: 'ab' * 64,
          ),
      ],
    );
  }

  @override
  Future<rust_api.TransportConfigDto> getTransportConfig() async {
    return const rust_api.TransportConfigDto(
      mdnsService: '_localauth._tcp.local.',
      tls13Port: 53319,
      bleGattServiceUuid: '0000fffd-0000-1000-8000-00805f9b34fb',
    );
  }

  @override
  Future<rust_api.VltInspectDto> inspectVltFile({required String path}) async {
    return rust_api.VltInspectDto(
      version: 1,
      cipher: 'ChaCha20Poly1305',
      directSlotCount: BigInt.from(2),
      quorumThresholdK: 2,
      quorumTotalN: 3,
      headerSha256Hex: 'ab' * 32,
      signatureValid: true,
    );
  }
}

Future<void> _loadRealFonts() async {
  const materialDir = r'C:\src\flutter\bin\cache\artifacts\material_fonts';

  Future<ByteData> readFont(String path) async {
    final bytes = await File(path).readAsBytes();
    return ByteData.sublistView(Uint8List.fromList(bytes));
  }

  final roboto = FontLoader('Roboto')
    ..addFont(readFont('$materialDir\\roboto-regular.ttf'))
    ..addFont(readFont('$materialDir\\roboto-medium.ttf'))
    ..addFont(readFont('$materialDir\\roboto-bold.ttf'));
  await roboto.load();

  final icons = FontLoader('MaterialIcons')
    ..addFont(readFont('$materialDir\\materialicons-regular.otf'));
  await icons.load();

  final mono = FontLoader('monospace')
    ..addFont(readFont(r'C:\Windows\Fonts\consola.ttf'));
  await mono.load();
}

Future<void> _capturePng(
  WidgetTester tester,
  GlobalKey boundaryKey,
  String outFileName,
) async {
  await tester.pumpAndSettle();
  final boundary = boundaryKey.currentContext!.findRenderObject()!
      as RenderRepaintBoundary;
  final outDir = Directory('../docs/screenshots');
  await tester.runAsync(() async {
    await outDir.create(recursive: true);
    final image = await boundary.toImage(pixelRatio: 2.0);
    final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
    final bytes = byteData!.buffer.asUint8List();
    await File('${outDir.path}/$outFileName').writeAsBytes(bytes);
    image.dispose();
  });
}

void main() {
  testWidgets('Capture real high-DPI LaVault screenshots with loaded fonts',
      (WidgetTester tester) async {
    await tester.runAsync(_loadRealFonts);

    tester.view.devicePixelRatio = 2.0;
    tester.view.physicalSize = const Size(824, 1784);
    addTearDown(tester.view.reset);

    final boundaryKey = GlobalKey();
    final controller = VaultController(
      api: DemoBackendApi(),
      keystore: DemoKeystore(),
      dbPathOverride: 'demo_showcase.db',
    );

    await tester.pumpWidget(
      RepaintBoundary(
        key: boundaryKey,
        child: LaVaultApp(controller: controller),
      ),
    );
    await _capturePng(tester, boundaryKey, '01_lock_screen.png');

    // Unlock and add two extra synthetic demo credentials
    await tester.tap(find.byKey(const Key('unlock_vault_btn')));
    await tester.pumpAndSettle();

    await controller.addCredential(
      title: 'Cloudflare Prod',
      username: 'ops@demo.local',
      password: 'Cf!Demo#2026Vault',
      totpSecretBase32: 'JBSWY3DPEHPK3PXP',
      algorithm: OtpAlgorithm.sha1,
      digits: 6,
    );
    await controller.addCredential(
      title: 'AWS Root Vault',
      username: 'sec-admin@demo.local',
      password: 'Aws#Root!Demo2026',
      totpSecretBase32: 'NB2W45DFOIZA====',
      algorithm: OtpAlgorithm.sha1,
      digits: 6,
    );
    await tester.pumpAndSettle();

    // Reveal first two entries so live TOTP codes & timers show cleanly
    await tester.tap(find.byKey(const Key('reveal_btn_entry_1')));
    await tester.tap(find.byKey(const Key('reveal_btn_entry_2')));
    await tester.pumpAndSettle();
    await _capturePng(tester, boundaryKey, '02_vault_totp.png');

    // Switch to Unlocker tab and stage a realistic 1-tap Wi-Fi LAN E2EE request
    await tester.tap(find.text('Unlocker'));
    await tester.pumpAndSettle();

    controller.lastWifiHost = '192.168.1.50:53319';
    controller.wifiStatus =
        'Ready: tap Approve Unlock below to unlock quarterly_taxes.pdf.vlt';
    controller.unlockQueue.insert(
      0,
      PendingUnlockRequest(
        id: 'req_wifi_live_01',
        channel: 'Wi-Fi LAN (E2EE)',
        requesterName: 'LaVault-PC (192.168.1.50)',
        targetFile: 'quarterly_taxes.pdf.vlt',
        slotType: '1-of-N Direct (Live Wi-Fi)',
        urRequestPayload: 'ur:lavault-req/oeadbaecgdjkfhlmnpqr',
        callbackUrl: 'http://192.168.1.50:53319',
      ),
    );
    await controller.unlockWithMasterPassword('LaVault-Master-2026');
    await tester.pumpWidget(
      RepaintBoundary(
        key: boundaryKey,
        child: LaVaultApp(controller: controller),
      ),
    );
    await tester.tap(find.text('Unlocker'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('wifi_host_field')),
      '192.168.1.50:53319',
    );
    await tester.pumpAndSettle();
    await _capturePng(tester, boundaryKey, '03_unlocker_wifi_1tap.png');

    // Now test Optical QR signing & capture Signed Response card
    await tester.ensureVisible(find.byKey(const Key('bcur_input_field')));
    await tester.enterText(
      find.byKey(const Key('bcur_input_field')),
      'ur:lavault-req/oeadbaecgdjkfhlmnpqrstuvwxyz',
    );
    await tester.ensureVisible(find.byKey(const Key('sign_bcur_btn')));
    await tester.tap(find.byKey(const Key('sign_bcur_btn')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('copy_ur_res_btn')));
    await tester.pumpAndSettle();
    await _capturePng(tester, boundaryKey, '04_unlocker_qr_signed.png');

    // Switch to Peers tab, generate Triple Recovery Kit, and capture
    await tester.tap(find.text('Peers'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('generate_recovery_btn')));
    await tester.tap(find.byKey(const Key('generate_recovery_btn')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('copy_guardian_2')));
    await tester.pumpAndSettle();
    await _capturePng(tester, boundaryKey, '05_peers_triple_recovery.png');

    controller.dispose();
  });
}
