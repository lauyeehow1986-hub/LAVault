import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../services/vault_backend_service.dart';
import '../src/rust/api.dart' as rust_api;

class UnlockerTab extends StatefulWidget {
  final VaultController controller;

  const UnlockerTab({super.key, required this.controller});

  @override
  State<UnlockerTab> createState() => _UnlockerTabState();
}

class _UnlockerTabState extends State<UnlockerTab> {
  final TextEditingController _urController = TextEditingController();
  String? _lastResponseUr;
  String? _qrError;
  rust_api.VltInspectDto? _inspectedVlt;

  @override
  void dispose() {
    _urController.dispose();
    super.dispose();
  }

  Future<void> _submitUrPayload(String ur) async {
    setState(() => _qrError = null);
    try {
      final res = await widget.controller.processBcurRequest(ur);
      setState(() => _lastResponseUr = res);
    } catch (e) {
      setState(() => _qrError = e.toString());
    }
  }

  Future<void> _pickAndInspectVlt() async {
    final picked = await FilePicker.pickFile(
      type: FileType.custom,
      allowedExtensions: ['vlt'],
    );
    final path = picked?.path;
    if (path == null) return;
    final info = await widget.controller.api.inspectVltFile(path: path);
    setState(() => _inspectedVlt = info);
  }

  void _openCameraQrScanner() {
    if (kIsWeb || Platform.isWindows || Platform.isLinux) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Camera QR scanner active on Android/iOS/macOS; paste ur:lavault-req below on desktop.'),
        ),
      );
      return;
    }
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SizedBox(
        height: 360,
        child: MobileScanner(
          onDetect: (capture) {
            final code = capture.barcodes.firstOrNull?.rawValue;
            if (code != null && code.toLowerCase().startsWith('ur:lavault-req/')) {
              Navigator.of(ctx).pop();
              _urController.text = code;
              _submitUrPayload(code);
            }
          },
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cfg = widget.controller.transportConfig;
    final queue = widget.controller.unlockQueue;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            Chip(
              avatar: const Icon(Icons.wifi, size: 16),
              label: Text(
                'mDNS ${cfg?.mdnsService ?? "_localauth._tcp.local."} :${cfg?.tls13Port ?? 53319}',
              ),
            ),
            Chip(
              avatar: const Icon(Icons.bluetooth, size: 16),
              label: Text(
                'BLE ${cfg?.bleGattServiceUuid.substring(0, 8) ?? "0000fffd"}...',
              ),
            ),
            const Chip(
              avatar: Icon(Icons.qr_code_2, size: 16),
              label: Text('bc-ur Optical QR'),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Text(
              'Incoming Unlock Queue',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const Spacer(),
            OutlinedButton.icon(
              onPressed: _pickAndInspectVlt,
              icon: const Icon(Icons.folder_open, size: 18),
              label: const Text('Inspect .vlt'),
            ),
          ],
        ),
        if (_inspectedVlt != null)
          Card(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            child: ListTile(
              title: Text('Header SHA-256: ${_inspectedVlt!.headerSha256Hex.substring(0, 16)}...'),
              subtitle: Text(
                'Cipher: ${_inspectedVlt!.cipher} | 1-of-N: ${_inspectedVlt!.directSlotCount} | '
                'Quorum: ${_inspectedVlt!.quorumThresholdK}-of-${_inspectedVlt!.quorumTotalN} | '
                'Ed25519 Valid: ${_inspectedVlt!.signatureValid}',
              ),
            ),
          ),
        const SizedBox(height: 6),
        ...queue.map(
          (req) => Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Chip(label: Text(req.channel)),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          '${req.requesterName} -> ${req.targetFile}',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                      ),
                    ],
                  ),
                  Text('Policy: ${req.slotType} | Status: ${req.status}'),
                  if (req.status == 'Pending')
                    Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        TextButton(
                          onPressed: () =>
                              widget.controller.respondToQueueItem(req.id, false),
                          child: const Text('Deny'),
                        ),
                        const SizedBox(width: 8),
                        FilledButton(
                          key: Key('approve_${req.id}'),
                          onPressed: () =>
                              widget.controller.respondToQueueItem(req.id, true),
                          child: const Text('Approve Unlock'),
                        ),
                      ],
                    ),
                ],
              ),
            ),
          ),
        ),
        const Divider(height: 24),
        Text(
          'Air-Gapped Optical QR (ur:lavault-req / ur:lavault-res)',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        TextField(
          key: const Key('bcur_input_field'),
          controller: _urController,
          maxLines: 2,
          decoration: const InputDecoration(
            labelText: 'Paste or scan ur:lavault-req/...',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _openCameraQrScanner,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan Camera QR'),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              key: const Key('sign_bcur_btn'),
              onPressed: () => _submitUrPayload(_urController.text),
              icon: const Icon(Icons.verified_user),
              label: const Text('Approve & Sign ur:lavault-res'),
            ),
          ],
        ),
        if (_qrError != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(_qrError!, style: const TextStyle(color: Colors.red)),
          ),
        if (_lastResponseUr != null) ...[
          const SizedBox(height: 12),
          Center(
            child: QrImageView(
              data: _lastResponseUr!,
              size: 180,
              backgroundColor: Colors.white,
            ),
          ),
          SelectableText(
            _lastResponseUr!,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          ),
        ],
      ],
      ),
    );
  }
}
