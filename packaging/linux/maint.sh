#!/bin/sh
# Sourced by package-manager scripts. Never initialize credentials or start a
# previously inactive server during package installation.
knock_systemd_running() {
    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

knock_configure() {
    install -d -m 700 /etc/knock-control /var/lib/knock-control
    if knock_systemd_running; then
        if [ -f /etc/systemd/system/knock-control-api.service ] || [ -f /usr/lib/systemd/system/knock-control-api.service ]; then
            systemctl disable --now knock-control-api.service || return 1
        fi
        systemctl daemon-reload || return 1
    fi
    if [ -f /etc/knock-control/settings.json ]; then
        /usr/sbin/knock-control migrate || return 1
        if knock_systemd_running; then
            systemctl try-restart knock-control.service || return 1
        fi
    fi
}

knock_remove() {
    if knock_systemd_running; then
        systemctl disable --now knock-control.service knock-control-firewall.service || return 1
    fi
    # Keep server-issued credentials, replay protection and existing firewall
    # protection. Removal must not expose previously protected services.
}
