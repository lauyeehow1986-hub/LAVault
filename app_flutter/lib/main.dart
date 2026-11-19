import 'package:flutter/material.dart';

import 'services/vault_backend_service.dart';
import 'tabs/peers_guardians_tab.dart';
import 'tabs/unlocker_tab.dart';
import 'tabs/vault_tab.dart';

void main() {
  runApp(LaVaultApp(controller: VaultController()));
}

class LaVaultApp extends StatefulWidget {
  final VaultController controller;

  const LaVaultApp({super.key, required this.controller});

  @override
  State<LaVaultApp> createState() => _LaVaultAppState();
}

class _LaVaultAppState extends State<LaVaultApp> {
  final TextEditingController _passwordCtrl =
      TextEditingController(text: 'LaVault-Master-2026');
  int _tabIndex = 0;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onChanged);
  }

  void _onChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onChanged);
    _passwordCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final ctrl = widget.controller;
    return MaterialApp(
      title: 'LaVault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.teal,
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: ctrl.isUnlocked
          ? Scaffold(
              appBar: AppBar(
                title: const Text('LaVault — Zero-Cloud Authenticator'),
                actions: [
                  IconButton(
                    key: const Key('lock_vault_btn'),
                    tooltip: 'Lock & Zeroize RAM',
                    onPressed: () => ctrl.lockVault(),
                    icon: const Icon(Icons.lock),
                  ),
                ],
              ),
              body: IndexedStack(
                index: _tabIndex,
                children: [
                  VaultTab(controller: ctrl),
                  UnlockerTab(controller: ctrl),
                  PeersGuardiansTab(controller: ctrl),
                ],
              ),
              bottomNavigationBar: NavigationBar(
                selectedIndex: _tabIndex,
                onDestinationSelected: (i) => setState(() => _tabIndex = i),
                destinations: const [
                  NavigationDestination(
                    icon: Icon(Icons.password),
                    label: 'Vault + TOTP',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.phonelink_lock),
                    label: 'Unlocker',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.group),
                    label: 'Peers',
                  ),
                ],
              ),
            )
          : Scaffold(
              body: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 420),
                  child: Card(
                    margin: const EdgeInsets.all(24),
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.security, size: 56),
                          const SizedBox(height: 12),
                          Text(
                            'LaVault',
                            style: const TextStyle(
                              fontSize: 28,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                          ),
                          const SizedBox(height: 6),
                          const Text(
                            'Zero-Cloud Password + TOTP Vault & Multi-User File Unlocker',
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 20),
                          TextField(
                            key: const Key('master_password_field'),
                            controller: _passwordCtrl,
                            obscureText: true,
                            decoration: const InputDecoration(
                              labelText: 'Master Password / PIN',
                              border: OutlineInputBorder(),
                            ),
                          ),
                          const SizedBox(height: 16),
                          SizedBox(
                            width: double.infinity,
                            child: FilledButton.icon(
                              key: const Key('unlock_vault_btn'),
                              onPressed: () => ctrl.unlockWithMasterPassword(
                                _passwordCtrl.text,
                              ),
                              icon: const Icon(Icons.fingerprint),
                              label: const Text('Unlock with Biometrics + Keystore'),
                            ),
                          ),
                          if (ctrl.lastError != null) ...[
                            const SizedBox(height: 12),
                            Text(
                              ctrl.lastError!,
                              style: const TextStyle(color: Colors.redAccent),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
    );
  }
}
