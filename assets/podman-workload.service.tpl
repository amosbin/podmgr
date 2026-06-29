[Unit]
Description=$USER (podman compose)

[Service]
Type=simple
WorkingDirectory=$COMPOSE_DIR

ExecStart=/usr/bin/podman compose -f $COMPOSE_FILE up
ExecStop=/usr/bin/podman compose -f $COMPOSE_FILE down

Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target