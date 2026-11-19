import 'dart:io';
import 'dart:typed_data';

import 'package:app_flutter/main.dart';
import 'package:app_flutter/services/hardware_keystore_service.dart';
import 'package:app_flutter/services/vault_backend_service.dart';
import 'package:app_flutter/src/rust/api.dart' as rust_api;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeKeystore implements VaultKeystoreBackend {
  @override
  Future<bool> authenticateWithBiometrics({required String reason}) async => true;

  @override
  Future<List<int>> getOrCreateHardwareSecret() async => List<int>.filled(32, 0x22);
}

class FakeBackendApi implements VaultBackendApi {
  final List<rust_api.VaultEntryInputDto> _stored = [];

  @override
  Future<void> ensureInitialized() async {}

  @override
  Future<rust_api.SessionInfoDto> createOrUnlockVault({
    required String dbPath,
    required String masterPassword,
    required List<int> hardwareSecret,
  }) async {
    return rust_api.SessionInfoDto(
      sessionId: 'sess_test_1',
      x25519PublicBytes: Uint8List(32),
      ed25519PublicBytes: Uint8List(32),
      x25519PublicHex: 'aa' * 32,
      ed25519PublicHex: 'bb' * 32,
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
          updatedAt: 0,
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
    return rust_api.UnlockedVaultEntryDto(
      id: entryId,
      title: e.title,
      username: e.username,
      password: e.password,
      totpCode: '94287082',
      totpRemainingSecs: BigInt.from(18),
      url: e.url,
      notes: e.notes,
    );
  }

  @override
  Future<String> approveBcurUnlockRequest({
    required String sessionId,
    required String urReq,
  }) async {
    return 'ur:lavault-res/hihihihi';
  }

  @override
  Future<rust_api.RecoveryKitDto> exportRecoveryKit({
    required String sessionId,
    required String rkfPassword,
    required List<String> guardianIds,
    required int thresholdK,
  }) async {
    return rust_api.RecoveryKitDto(
      bip3924Words: List.filled(24, 'abandon').join(' '),
      rkfBytes: Uint8List(96),
      guardianCapsules: [
        for (var i = 0; i < guardianIds.length; i++)
          rust_api.GuardianCapsuleDto(
            guardianId: guardianIds[i],
            shareIndex: i + 1,
            thresholdK: thresholdK,
            totalN: guardianIds.length,
            slip39Uri: 'lavault-share://v1/$thresholdK-of-${guardianIds.length}/idx-${i + 1}/abcd.1234',
            signatureHex: 'cc' * 64,
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
      headerSha256Hex: 'dd' * 32,
      signatureValid: true,
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
}

void main() {
  testWidgets('LaVault 3-tab workflow: unlock, TOTP reveal, QR approve, recovery kit, and lock',
      (WidgetTester tester) async {
    final controller = VaultController(
      api: FakeBackendApi(),
      keystore: FakeKeystore(),
      dbPathOverride: 'test_vault.db',
    );

    await tester.pumpWidget(LaVaultApp(controller: controller));
    expect(find.text('LaVault'), findsOneWidget);

    await tester.tap(find.byKey(const Key('unlock_vault_btn')));
    await tester.pumpAndSettle();
    expect(controller.lastError, isNull);
    expect(controller.isUnlocked, isTrue);

    // Tab 1: Vault + TOTP
    expect(find.text('GitHub Work'), findsOneWidget);
    await tester.tap(find.byKey(const Key('reveal_btn_entry_1')));
    await tester.pumpAndSettle();
    expect(find.text('94287082'), findsOneWidget);
    await tester.tap(find.byKey(const Key('delete_btn_entry_1')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm_delete_entry_btn')));
    await tester.pumpAndSettle();
    expect(find.text('GitHub Work'), findsNothing);

    // Tab 2: Unlocker (Wi-Fi + BLE queue + Air-Gapped QR)
    await tester.tap(find.text('Unlocker'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Workstation-Win11'), findsOneWidget);
    await tester.ensureVisible(find.byKey(const Key('approve_req_wifi_01')));
    await tester.tap(find.byKey(const Key('approve_req_wifi_01')));
    await tester.pumpAndSettle();

    await tester.ensureVisible(find.byKey(const Key('bcur_input_field')));
    await tester.enterText(
      find.byKey(const Key('bcur_input_field')),
      'ur:lavault-req/abc',
    );
    await tester.ensureVisible(find.byKey(const Key('sign_bcur_btn')));
    await tester.tap(find.byKey(const Key('sign_bcur_btn')));
    await tester.pumpAndSettle();
    expect(find.text('ur:lavault-res/hihihihi'), findsOneWidget);
    expect(find.byKey(const Key('copy_ur_res_btn')), findsOneWidget);

    // Tab 3: Peers & Guardians + Triple Recovery
    await tester.tap(find.text('Peers'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('copy_this_device_key_btn')), findsOneWidget);
    await tester.tap(find.text('Peers'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('generate_recovery_btn')));
    await tester.tap(find.byKey(const Key('generate_recovery_btn')));
    await tester.pumpAndSettle();
    expect(find.textContaining('abandon abandon'), findsOneWidget);
    await tester.ensureVisible(find.textContaining('guardian_alice (Share 1/3'));
    expect(find.textContaining('guardian_alice (Share 1/3'), findsOneWidget);

    // Lock session
    await tester.tap(find.byKey(const Key('lock_vault_btn')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('unlock_vault_btn')), findsOneWidget);
    controller.dispose();
  });

  group('resolveVaultDbPath', () {
    test('prefers native Android directory even when supportDirProvider throws', () async {
      final tmp = Directory.systemTemp.createTempSync('lavault_android_native_');
      addTearDown(() => tmp.deleteSync(recursive: true));

      final resolved = await resolveVaultDbPath(
        isAndroidOverride: true,
        nativeAndroidDirProvider: () async => tmp.path,
        supportDirProvider: () async => throw Exception('MissingPluginException'),
        docsDirProvider: () async => throw Exception('MissingPluginException'),
        tempDirProvider: () async => throw Exception('MissingPluginException'),
      );

      expect(resolved, '${tmp.path}/lavault_mobile.db');
    });

    test('falls back to docsDirProvider then tempDirProvider when native/support fail', () async {
      final docsDir = Directory.systemTemp.createTempSync('lavault_docs_');
      final tempDir = Directory.systemTemp.createTempSync('lavault_temp_');
      addTearDown(() {
        docsDir.deleteSync(recursive: true);
        tempDir.deleteSync(recursive: true);
      });

      final fromDocs = await resolveVaultDbPath(
        isAndroidOverride: true,
        nativeAndroidDirProvider: () async => null,
        supportDirProvider: () async => throw Exception('jni error'),
        docsDirProvider: () async => docsDir,
        tempDirProvider: () async => tempDir,
      );
      expect(fromDocs, '${docsDir.path}/lavault_mobile.db');

      final fromTemp = await resolveVaultDbPath(
        isAndroidOverride: true,
        nativeAndroidDirProvider: () async => null,
        supportDirProvider: () async => throw Exception('jni error'),
        docsDirProvider: () async => throw Exception('docs error'),
        tempDirProvider: () async => tempDir,
      );
      expect(fromTemp, '${tempDir.path}/lavault_mobile.db');
    });

    test('throws StateError when all Android directory providers fail', () async {
      await expectLater(
        resolveVaultDbPath(
          isAndroidOverride: true,
          nativeAndroidDirProvider: () async => null,
          supportDirProvider: () async => throw Exception('support fail'),
          docsDirProvider: () async => throw Exception('docs fail'),
          tempDirProvider: () async => throw Exception('temp fail'),
        ),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Unable to resolve writable Android storage directory'),
          ),
        ),
      );
    });
  });
}
