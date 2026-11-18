import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/vault_backend_service.dart';
import '../src/rust/otp.dart';

class VaultTab extends StatefulWidget {
  final VaultController controller;

  const VaultTab({super.key, required this.controller});

  @override
  State<VaultTab> createState() => _VaultTabState();
}

class _VaultTabState extends State<VaultTab> {
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _confirmDelete(String entryId, String title) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Vault Entry'),
        content: Text('Delete "$title" permanently?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_delete_entry_btn'),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await widget.controller.deleteCredential(entryId);
    }
  }

  Future<void> _showAddDialog() async {
    final titleCtrl = TextEditingController();
    final userCtrl = TextEditingController();
    final passCtrl = TextEditingController();
    final totpCtrl = TextEditingController();
    OtpAlgorithm alg = OtpAlgorithm.sha1;
    int digits = 6;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Add Password + TOTP Entry'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: titleCtrl,
                  decoration: const InputDecoration(labelText: 'Service / Title'),
                ),
                TextField(
                  controller: userCtrl,
                  decoration: const InputDecoration(labelText: 'Username / Email'),
                ),
                TextField(
                  controller: passCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Password'),
                ),
                TextField(
                  controller: totpCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Base32 TOTP Secret (optional)',
                  ),
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    DropdownButton<OtpAlgorithm>(
                      value: alg,
                      onChanged: (v) => setDialogState(() => alg = v ?? alg),
                      items: const [
                        DropdownMenuItem(value: OtpAlgorithm.sha1, child: Text('SHA-1')),
                        DropdownMenuItem(value: OtpAlgorithm.sha256, child: Text('SHA-256')),
                        DropdownMenuItem(value: OtpAlgorithm.sha512, child: Text('SHA-512')),
                      ],
                    ),
                    const SizedBox(width: 12),
                    DropdownButton<int>(
                      value: digits,
                      onChanged: (v) => setDialogState(() => digits = v ?? digits),
                      items: const [
                        DropdownMenuItem(value: 6, child: Text('6 digits')),
                        DropdownMenuItem(value: 7, child: Text('7 digits')),
                        DropdownMenuItem(value: 8, child: Text('8 digits')),
                      ],
                    ),
                  ],
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                await widget.controller.addCredential(
                  title: titleCtrl.text.trim(),
                  username: userCtrl.text.trim(),
                  password: passCtrl.text,
                  totpSecretBase32: totpCtrl.text.trim(),
                  algorithm: alg,
                  digits: digits,
                );
                if (ctx.mounted) Navigator.of(ctx).pop();
              },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final entries = widget.controller.entries;
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  key: const Key('vault_search_field'),
                  controller: _searchController,
                  decoration: const InputDecoration(
                    prefixIcon: Icon(Icons.search),
                    hintText: 'Search vault passwords & TOTP...',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  onChanged: (q) => widget.controller.search(q),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                key: const Key('add_credential_btn'),
                onPressed: _showAddDialog,
                icon: const Icon(Icons.add),
                label: const Text('Add'),
              ),
            ],
          ),
        ),
        Expanded(
          child: entries.isEmpty
              ? const Center(child: Text('No vault entries yet.'))
              : ListView.builder(
                  itemCount: entries.length,
                  itemBuilder: (context, idx) {
                    final summary = entries[idx];
                    final unlocked = widget.controller.unlockedCache[summary.id];
                    final remaining = unlocked?.totpRemainingSecs?.toInt() ?? 30;
                    final progress = (remaining / 30.0).clamp(0.0, 1.0);

                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        summary.title,
                                        style: Theme.of(context).textTheme.titleMedium,
                                      ),
                                      Text(
                                        summary.username,
                                        style: Theme.of(context).textTheme.bodySmall,
                                      ),
                                    ],
                                  ),
                                ),
                                IconButton(
                                  key: Key('reveal_btn_${summary.id}'),
                                  tooltip: unlocked == null ? 'Unlock & Reveal' : 'Hide',
                                  onPressed: () =>
                                      widget.controller.toggleRevealEntry(summary.id),
                                  icon: Icon(
                                    unlocked == null ? Icons.lock_open : Icons.visibility_off,
                                  ),
                                ),
                                IconButton(
                                  key: Key('delete_btn_${summary.id}'),
                                  tooltip: 'Delete Entry',
                                  onPressed: () =>
                                      _confirmDelete(summary.id, summary.title),
                                  icon: const Icon(Icons.delete_outline),
                                ),
                              ],
                            ),
                            if (unlocked != null) ...[
                              const Divider(),
                              Row(
                                children: [
                                  Expanded(
                                    child: SelectableText(
                                      'Password: ${unlocked.password}',
                                      style: const TextStyle(fontFamily: 'monospace'),
                                    ),
                                  ),
                                  IconButton(
                                    tooltip: 'Copy Password',
                                    onPressed: () {
                                      Clipboard.setData(
                                        ClipboardData(text: unlocked.password),
                                      );
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        const SnackBar(content: Text('Password copied')),
                                      );
                                    },
                                    icon: const Icon(Icons.copy, size: 18),
                                  ),
                                ],
                              ),
                              if (unlocked.totpCode != null) ...[
                                const SizedBox(height: 8),
                                Row(
                                  children: [
                                    SizedBox(
                                      width: 28,
                                      height: 28,
                                      child: Stack(
                                        alignment: Alignment.center,
                                        children: [
                                          CircularProgressIndicator(
                                            value: progress,
                                            strokeWidth: 3,
                                          ),
                                          Text(
                                            '$remaining',
                                            style: const TextStyle(fontSize: 10),
                                          ),
                                        ],
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    Text(
                                      unlocked.totpCode!,
                                      style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                                            fontFamily: 'monospace',
                                            letterSpacing: 3,
                                            fontWeight: FontWeight.bold,
                                          ),
                                    ),
                                    const Spacer(),
                                    IconButton(
                                      tooltip: 'Copy TOTP',
                                      onPressed: () {
                                        Clipboard.setData(
                                          ClipboardData(text: unlocked.totpCode!),
                                        );
                                        ScaffoldMessenger.of(context).showSnackBar(
                                          const SnackBar(content: Text('TOTP code copied')),
                                        );
                                      },
                                      icon: const Icon(Icons.copy, size: 18),
                                    ),
                                  ],
                                ),
                              ],
                            ],
                          ],
                        ),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}
