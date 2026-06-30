[Unit]
Description=podmgr tenant relay daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/podmgr-relay-tenantd --listen {{TENANT_RELAY_SOCKET}} --upstream {{TENANT_UPSTREAM}}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={{TENANT_SOCKET_DIR}}

[Install]
WantedBy=default.target
