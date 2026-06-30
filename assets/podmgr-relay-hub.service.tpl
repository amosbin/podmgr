[Unit]
Description=podmgr relay hub daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/podmgr-relay-hubd --runtime-conf {{RUNTIME_CONF}} --socket {{HUB_SOCKET}}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={{RUNTIME_CONF_DIR}} {{SOCKET_DIR}}

[Install]
WantedBy=default.target
