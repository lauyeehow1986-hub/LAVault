import 'dart:io';

import 'package:app_flutter/services/vault_backend_service.dart';
import 'package:app_flutter/src/rust/api.dart' as rust_api;
import 'package:app_flutter/src/rust/otp.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Live Rust FFI bridge executes Vault + TOTP + Recovery via vault_core.dll', () async {
    final backend = RustVaultBackendApi();
    await backend.ensureInitialized();

    final totp = await rust_api.verifyTotpVectorForTest();
    expect(totp, '94287082');

    final cfg = await backend.getTransportConfig();
    expect(cfg.mdnsService, '_localauth._tcp.local.');
    expect(cfg.tls13Port, 53319);
    expect(cfg.bleGattServiceUuid, '0000fffd-0000-1000-8000-00805f9b34fb');

    final tmpDir = Directory.systemTemp.createTempSync('lavault_ffi_');
    try {
      final dbPath = '${tmpDir.path}/ffi_vault.db';
      final session = await backend.createOrUnlockVault(
        dbPath: dbPath,
        masterPassword: 'FFI-Test-Password-2026',
        hardwareSecret: List<int>.filled(32, 0x3A),
      );

      final entryId = await backend.addVaultEntry(
        sessionId: session.sessionId,
        entry: rust_api.VaultEntryInputDto(
          title: 'FFI GitHub',
          username: 'ffi@lavault.local',
          password: 'Secret-FFI-Password!',
          totpSecretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          totpAlgorithm: OtpAlgorithm.sha1,
          totpDigits: 8,
          totpPeriodSecs: BigInt.from(30),
          url: null,
          notes: null,
        ),
      );

      final unlocked = await backend.unlockVaultEntryAt(
        sessionId: session.sessionId,
        entryId: entryId,
        unixTime: BigInt.from(59),
      );
      expect(unlocked.password, 'Secret-FFI-Password!');
      expect(unlocked.totpCode, '94287082');
      expect(unlocked.totpRemainingSecs, BigInt.one);

      final kit = await backend.exportRecoveryKit(
        sessionId: session.sessionId,
        rkfPassword: 'rkf-test-password',
        guardianIds: ['alice', 'bob', 'charlie'],
        thresholdK: 2,
      );
      expect(kit.bip3924Words.split(' ').length, 24);
      expect(kit.guardianCapsules.length, 3);

      await backend.deleteVaultEntry(
        sessionId: session.sessionId,
        entryId: entryId,
      );
      final remaining = await backend.listVaultEntries(sessionId: session.sessionId);
      expect(remaining, isEmpty);

      await backend.lockSession(sessionId: session.sessionId);
    } finally {
      tmpDir.deleteSync(recursive: true);
    }
  });
}
