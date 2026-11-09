package com.sucrune.probe

class IsolatedProbeService : ProbeService() {
    override val executionIdentity = "isolated_service"
}
