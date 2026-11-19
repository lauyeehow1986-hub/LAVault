import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../services/vault_backend_service.dart';

class PeersGuardiansTab extends StatefulWidget {
  final VaultController controller;

  const PeersGuardiansTab({super.key, required this.controller});

  @override
  State<PeersGuardiansTab> createState() => _PeersGuardiansTabState();
}

class _PeersGuardiansTabState extends State<PeersGuardiansTab> {
  final TextEditingController _rkfPassCtrl =
      TextEditingController(text: 'Recovery-Keyfile-Pass#2026');

  @override
  void dispose() {
    _rkfPassCtrl.dispose();
    super.dispose();
  }

  Future<void> _showAddPeerDialog() async {
    final idCtrl = TextEditingController();
    final keyCtrl = TextEditingController();
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Authorize 1-of-N Peer'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: idCtrl,
              decoration: const InputDecoration(labelText: 'Peer ID'),
            ),
            TextField(
              controller: keyCtrl,
              decoration: const InputDecoration(labelText: 'X25519 Public Key (hex)'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              widget.controller.addAuthorizedPeer(
                idCtrl.text.trim(),
                keyCtrl.text.trim(),
                'Wi-Fi mDNS + TLS 1.3',
              );
              Navigator.of(ctx).pop();
            },
            child: const Text('Authorize'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final peers = widget.controller.peers;
    final kit = widget.controller.recoveryKit;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
        Row(
          children: [
            Text(
              'Authorized 1-of-N Peers',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const Spacer(),
            FilledButton.icon(
              key: const Key('add_peer_btn'),
              onPressed: _showAddPeerDialog,
              icon: const Icon(Icons.person_add, size: 18),
              label: const Text('Add Peer'),
            ),
          ],
        ),
        const SizedBox(height: 6),
        ...peers.map(
          (p) => Card(
            child: ListTile(
              leading: const Icon(Icons.devices),
              title: Text(p.id),
              subtitle: Text('${p.transport}\n${p.x25519Hex}'),
              isThreeLine: true,
              trailing: p.id == 'this_device'
                  ? Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          key: const Key('copy_this_device_key_btn'),
                          icon: const Icon(Icons.copy, size: 18),
                          tooltip: 'Copy X25519 Key',
                          onPressed: () {
                            Clipboard.setData(ClipboardData(text: p.x25519Hex));
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('Copied this_device X25519 key'),
                              ),
                            );
                          },
                        ),
                        const Chip(label: Text('Primary')),
                      ],
                    )
                  : IconButton(
                      icon: const Icon(Icons.delete_outline),
                      onPressed: () =>
                          widget.controller.removeAuthorizedPeer(p.id),
                    ),
            ),
          ),
        ),
        const Divider(height: 24),
        Text(
          'K-of-N Shamir Quorum & Triple Recovery',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        Text(
          'Quorum Policy: ${widget.controller.quorumThresholdK}-of-${widget.controller.guardianIds.length} '
          'Guardians (${widget.controller.guardianIds.join(", ")})',
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _rkfPassCtrl,
          obscureText: true,
          decoration: const InputDecoration(
            labelText: '.rkf Recovery Keyfile Passphrase (Argon2id)',
            border: OutlineInputBorder(),
            isDense: true,
          ),
        ),
        const SizedBox(height: 8),
        FilledButton.icon(
          key: const Key('generate_recovery_btn'),
          onPressed: () =>
              widget.controller.generateRecoveryKit(_rkfPassCtrl.text),
          icon: const Icon(Icons.shield),
          label: const Text('Generate Triple Recovery Kit (BIP-39 + .rkf + SLIP-39)'),
        ),
        if (kit != null) ...[
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '1. Paper Backup (24-Word BIP-0039 Mnemonic)',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 4),
                  SelectableText(
                    kit.bip3924Words,
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                  const Divider(),
                  Text(
                    '2. Encrypted Recovery Keyfile (.rkf)',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  Text('Size: ${kit.rkfBytes.length} bytes (Argon2id + XChaCha20-Poly1305)'),
                  const Divider(),
                  Text(
                    '3. M-of-N Guardian QR Shares (GF(256) 0x11B)',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 8),
                  ...kit.guardianCapsules.map(
                    (g) => Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Row(
                        children: [
                          QrImageView(
                            data: g.slip39Uri,
                            size: 88,
                            backgroundColor: Colors.white,
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  '${g.guardianId} (Share ${g.shareIndex}/${g.totalN}, K=${g.thresholdK})',
                                  style: const TextStyle(fontWeight: FontWeight.bold),
                                ),
                                Text(
                                  g.slip39Uri,
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(
                                    fontFamily: 'monospace',
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
      ),
    );
  }
}
