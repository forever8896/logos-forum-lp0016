// Logos Forum — Basecamp UI plugin entry. Tabs:
//   Posts: feed + composer
//   Moderate: per-post strike issue + aggregate buttons
//   Admin: create instance / generate identity / register / slash search
//
// Bound to the `backend` context property (see ForumPlugin.cpp).
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: root
    color: "#0e0e10"
    anchors.fill: parent

    // ─── Theme ──────────────────────────────────────────────────────────
    readonly property color accent:   "#4ea1ff"
    readonly property color subtle:   "#7c7d80"
    readonly property color panel:    "#1a1a1d"
    readonly property color border:   "#2a2a2e"
    readonly property color textCol:  "#e6e6e8"
    readonly property color danger:   "#ff5a5a"
    readonly property color success:  "#3ed598"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        // ─── Header ────────────────────────────────────────────────────
        RowLayout {
            Layout.fillWidth: true
            Label {
                text: "Logos Forum"
                color: root.textCol
                font.pixelSize: 22
                font.bold: true
            }
            Label {
                text: backend.instanceExists
                    ? ("· " + backend.instanceLabel
                        + "  K=" + backend.k + "  N-of-M=" + backend.n + "/" + backend.m
                        + "  members=" + backend.memberCount
                        + "  revoked=" + backend.revocationCount)
                    : "· (no instance loaded)"
                color: root.subtle
                font.pixelSize: 12
                Layout.alignment: Qt.AlignVCenter
                Layout.leftMargin: 8
            }
            Item { Layout.fillWidth: true }
            BusyIndicator { running: backend.busy; visible: backend.busy }
            Button { text: "Refresh"; onClicked: backend.refreshState() }
        }

        // ─── Identity strip ────────────────────────────────────────────
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 36
            color: root.panel
            border.color: root.border
            border.width: 1
            radius: 4

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 10
                anchors.rightMargin: 10
                spacing: 8
                Label {
                    text: backend.haveIdentity
                        ? ("identity: " + backend.commitmentHex.substring(0, 16) + "…")
                        : "identity: (none — generate one)"
                    color: backend.haveIdentity ? root.success : root.subtle
                    font.family: "monospace"
                }
                Item { Layout.fillWidth: true }
                Button { text: "Generate"; onClicked: backend.generateIdentity() }
            }
        }

        // ─── Last status ───────────────────────────────────────────────
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: visible ? 28 : 0
            color: root.panel
            border.color: backend.lastError ? root.danger : root.border
            border.width: 1
            radius: 4
            visible: backend.lastError !== "" || backend.lastTxHash !== ""
            Label {
                anchors.fill: parent
                anchors.margins: 6
                text: backend.lastError !== ""
                    ? ("⚠ " + backend.lastError)
                    : ("✓ tx " + backend.lastTxHash)
                color: backend.lastError ? root.danger : root.success
                font.family: "monospace"
                font.pixelSize: 11
                elide: Text.ElideRight
                wrapMode: Text.NoWrap
            }
        }

        // ─── Tabs ──────────────────────────────────────────────────────
        TabBar {
            id: tabs
            Layout.fillWidth: true
            background: Rectangle { color: root.panel; border.color: root.border }
            TabButton { text: "Posts" }
            TabButton { text: "Moderate" }
            TabButton { text: "History" + (backend.pendingRetries > 0 ? " (" + backend.pendingRetries + " queued)" : "") }
            TabButton { text: "Admin" }
        }

        StackLayout {
            id: stack
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabs.currentIndex

            // ─── Posts tab ─────────────────────────────────────────────
            ColumnLayout {
                spacing: 6
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 56
                    color: root.panel
                    border.color: root.border
                    border.width: 1
                    radius: 4
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 6
                        TextField {
                            id: composer
                            Layout.fillWidth: true
                            placeholderText: "Write an anonymous post…"
                            color: root.textCol
                            background: Rectangle { color: "#111114"; border.color: root.border; radius: 3 }
                        }
                        Button {
                            text: "Post"
                            enabled: backend.haveIdentity && composer.text.length > 0 && !backend.busy
                            onClicked: {
                                backend.publishPost(composer.text)
                                composer.text = ""
                            }
                        }
                    }
                }

                ListView {
                    id: postsView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    model: backend.posts
                    spacing: 4
                    delegate: Rectangle {
                        width: postsView.width
                        height: 60
                        color: root.panel
                        border.color: modelData.complete ? root.danger : root.border
                        border.width: 1
                        radius: 4
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 8
                            spacing: 2
                            Label {
                                text: modelData.body
                                color: root.textCol
                                font.pixelSize: 14
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                            Label {
                                text: "msg_id " + modelData.msg_id_hex.substring(0, 16) + "…"
                                    + "  · shares: " + (modelData.shares ? modelData.shares.length : 0)
                                    + "/" + backend.n
                                    + (modelData.complete ? "  · CERT COMPLETE" : "")
                                color: root.subtle
                                font.family: "monospace"
                                font.pixelSize: 10
                            }
                        }
                    }
                }
            }

            // ─── Moderate tab ──────────────────────────────────────────
            ColumnLayout {
                spacing: 6
                Label {
                    text: "Moderation panel — issue strike shares against posts. Set FORUM_MODERATOR_SHARE_SECRET_HEX before launching to enable."
                    color: root.subtle
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                RowLayout {
                    Layout.fillWidth: true
                    Label { text: "Your moderator index (1..M):"; color: root.textCol }
                    SpinBox {
                        id: modIndexSpin
                        from: 1; to: Math.max(1, backend.m)
                        value: 1
                    }
                }
                ListView {
                    id: modView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    model: backend.posts
                    spacing: 4
                    delegate: Rectangle {
                        width: modView.width
                        height: 64
                        color: root.panel
                        border.color: root.border
                        border.width: 1
                        radius: 4
                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 8
                            spacing: 8
                            ColumnLayout {
                                Layout.fillWidth: true
                                Label { text: modelData.body; color: root.textCol; elide: Text.ElideRight }
                                Label {
                                    text: "shares " + (modelData.shares ? modelData.shares.length : 0) + "/" + backend.n
                                    color: root.subtle
                                    font.family: "monospace"
                                    font.pixelSize: 11
                                }
                            }
                            Button {
                                text: "Issue strike"
                                enabled: !backend.busy && (!modelData.complete)
                                onClicked: backend.issueStrike(index, modIndexSpin.value)
                            }
                            Button {
                                text: "Aggregate"
                                enabled: !backend.busy
                                    && modelData.shares
                                    && modelData.shares.length >= backend.n
                                    && !modelData.complete
                                onClicked: backend.aggregateCertificate(index)
                            }
                        }
                    }
                }
            }

            // ─── History tab ───────────────────────────────────────────
            ColumnLayout {
                spacing: 6
                Label {
                    text: "Moderation history — strikes, slashes, registrations, and queued retries (most recent first)."
                    color: root.subtle
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                ListView {
                    id: histView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    model: backend.history
                    spacing: 2
                    delegate: Rectangle {
                        width: histView.width
                        height: 44
                        color: root.panel
                        border.color: modelData.kind === "error" ? root.danger
                                    : modelData.kind === "queued" ? "#996633"
                                    : root.border
                        border.width: 1
                        radius: 3
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 6
                            spacing: 1
                            RowLayout {
                                Label { text: modelData.timestamp; color: root.subtle; font.family: "monospace"; font.pixelSize: 10 }
                                Label { text: "·"; color: root.subtle }
                                Label { text: modelData.kind; color: root.accent; font.bold: true; font.pixelSize: 11 }
                            }
                            Label {
                                text: JSON.stringify(modelData.detail)
                                color: root.textCol
                                font.family: "monospace"
                                font.pixelSize: 10
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            // ─── Admin tab ─────────────────────────────────────────────
            ScrollView {
                clip: true
                ColumnLayout {
                    spacing: 12
                    width: stack.width - 24

                    // Create instance
                    GroupBox {
                        title: "Create instance (admin)"
                        Layout.fillWidth: true
                        background: Rectangle { color: root.panel; border.color: root.border; radius: 4 }
                        label: Label { text: "Create instance (admin)"; color: root.textCol; font.bold: true }
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 6
                            TextField { id: adminId;     placeholderText: "Admin account id (Public/…)"; Layout.fillWidth: true; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            TextField { id: instLabel;   placeholderText: "Instance label";              Layout.fillWidth: true; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            RowLayout {
                                Label { text: "K"; color: root.textCol }
                                SpinBox { id: kSp; from: 2; to: 16; value: 5 }
                                Label { text: "N"; color: root.textCol }
                                SpinBox { id: nSp; from: 1; to: 32; value: 3 }
                                Label { text: "M"; color: root.textCol }
                                SpinBox { id: mSp; from: 1; to: 32; value: 5 }
                                Label { text: "D"; color: root.textCol }
                                SpinBox { id: dSp; from: 4; to: 24; value: 12 }
                            }
                            TextField { id: stakeF;      placeholderText: "Stake amount";                Layout.fillWidth: true; text: "1000"; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            TextField { id: modPksF;     placeholderText: "Moderator pubkeys (33-byte hex, comma-separated)"; Layout.fillWidth: true; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            Button {
                                text: "Create instance"
                                enabled: !backend.busy && adminId.text.length > 0 && modPksF.text.length > 0
                                onClicked: backend.createInstance(
                                    adminId.text, kSp.value, nSp.value, mSp.value, dSp.value,
                                    stakeF.text, instLabel.text,
                                    modPksF.text.split(/[ ,]+/).filter(s => s.length > 0))
                            }
                        }
                    }

                    // Register
                    GroupBox {
                        title: "Register self"
                        Layout.fillWidth: true
                        background: Rectangle { color: root.panel; border.color: root.border; radius: 4 }
                        label: Label { text: "Register self"; color: root.textCol; font.bold: true }
                        RowLayout {
                            anchors.fill: parent
                            TextField {
                                id: regSigner
                                placeholderText: "Signer account id (Public/…)"
                                Layout.fillWidth: true
                                color: root.textCol
                                background: Rectangle { color: "#111114"; border.color: root.border }
                            }
                            Button {
                                text: "Register"
                                enabled: !backend.busy && backend.haveIdentity && regSigner.text.length > 0
                                onClicked: backend.registerSelf(regSigner.text)
                            }
                        }
                    }

                    // Slash search
                    GroupBox {
                        title: "Slash search & submit"
                        Layout.fillWidth: true
                        background: Rectangle { color: root.panel; border.color: root.border; radius: 4 }
                        label: Label { text: "Slash search & submit"; color: root.textCol; font.bold: true }
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 6
                            TextField { id: slashSigner;    placeholderText: "Submitter account (Public/…)";   Layout.fillWidth: true; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            TextField { id: slashRecipient; placeholderText: "Slash recipient (Public/…)";     Layout.fillWidth: true; color: root.textCol; background: Rectangle { color: "#111114"; border.color: root.border } }
                            Button {
                                text: "Search & submit slash"
                                enabled: !backend.busy && slashSigner.text.length > 0 && slashRecipient.text.length > 0
                                onClicked: backend.runSlashSearch(slashSigner.text, slashRecipient.text)
                            }
                            Label {
                                text: "Slash requires ≥ K complete certificates in the local pool. The search tries every K-subset; a match means a real member was reconstructed."
                                color: root.subtle
                                font.pixelSize: 10
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }
        }
    }
}
