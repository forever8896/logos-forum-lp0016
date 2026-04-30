#pragma once

#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantList>

class LogosAPI;

/// Backend object exposed to QML as `backend`. Owns:
///   - environment (wallet path, sequencer URL, program ID)
///   - identity (this user's polynomial coefficients, persisted via env vars
///     so each Basecamp user-dir gets its own member identity for free)
///   - chain state (member count, member root, revocation list, pooled stake)
///   - off-chain state (posts feed, certificate-share pool, complete certs)
///
/// Slots dispatch to the Rust FFI via QtConcurrent::run so the UI never
/// blocks on chain/crypto work. Results are surfaced via property-change
/// signals plus the `txSuccess` / `txError` channels.
class ForumBackend : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString programIdHex     READ programIdHex     NOTIFY programIdHexChanged)
    Q_PROPERTY(bool    instanceExists   READ instanceExists   NOTIFY stateChanged)
    Q_PROPERTY(QString instanceLabel    READ instanceLabel    NOTIFY stateChanged)
    Q_PROPERTY(int     k                READ k                NOTIFY stateChanged)
    Q_PROPERTY(int     n                READ n                NOTIFY stateChanged)
    Q_PROPERTY(int     m                READ m                NOTIFY stateChanged)
    Q_PROPERTY(int     d                READ d                NOTIFY stateChanged)
    Q_PROPERTY(QString stakeAmount      READ stakeAmount      NOTIFY stateChanged)
    Q_PROPERTY(QString memberRootHex    READ memberRootHex    NOTIFY stateChanged)
    Q_PROPERTY(int     memberCount      READ memberCount      NOTIFY stateChanged)
    Q_PROPERTY(int     revocationCount  READ revocationCount  NOTIFY stateChanged)
    Q_PROPERTY(QString pooledStake      READ pooledStake      NOTIFY stateChanged)
    Q_PROPERTY(QString modPubkeyHex     READ modPubkeyHex     NOTIFY stateChanged)
    Q_PROPERTY(bool    haveIdentity     READ haveIdentity     NOTIFY identityChanged)
    Q_PROPERTY(QString commitmentHex    READ commitmentHex    NOTIFY identityChanged)
    Q_PROPERTY(bool    busy             READ busy             NOTIFY busyChanged)
    Q_PROPERTY(QString lastError        READ lastError        NOTIFY lastErrorChanged)
    Q_PROPERTY(QString lastTxHash       READ lastTxHash       NOTIFY lastTxHashChanged)
    Q_PROPERTY(QVariantList posts       READ posts            NOTIFY postsChanged)
    Q_PROPERTY(QVariantList revocationList READ revocationList NOTIFY stateChanged)
    Q_PROPERTY(QVariantList history     READ history          NOTIFY historyChanged)
    Q_PROPERTY(int     pendingRetries   READ pendingRetries   NOTIFY pendingRetriesChanged)

public:
    explicit ForumBackend(LogosAPI* api, QObject* parent = nullptr);
    ~ForumBackend() override;

    QString programIdHex()    const { return m_programIdHex; }
    bool    instanceExists()  const { return !m_instanceLabel.isEmpty(); }
    QString instanceLabel()   const { return m_instanceLabel; }
    int     k()               const { return m_k; }
    int     n()               const { return m_n; }
    int     m()               const { return m_m; }
    int     d()               const { return m_d; }
    QString stakeAmount()     const { return m_stakeAmount; }
    QString memberRootHex()   const { return m_memberRootHex; }
    int     memberCount()     const { return m_memberCount; }
    int     revocationCount() const { return m_revocationCount; }
    QString pooledStake()     const { return m_pooledStake; }
    QString modPubkeyHex()    const { return m_modPubkeyHex; }
    bool    haveIdentity()    const { return !m_coeffsHex.isEmpty(); }
    QString commitmentHex()   const { return m_commitmentHex; }
    bool    busy()            const { return m_busy; }
    QString lastError()       const { return m_lastError; }
    QString lastTxHash()      const { return m_lastTxHash; }
    QVariantList posts()      const { return m_posts; }
    QVariantList revocationList() const { return m_revocationList; }
    QVariantList history()    const { return m_history; }
    int     pendingRetries()  const { return m_pendingActions.size(); }

    // ── User-facing slots ────────────────────────────────────────────────

    /// Create a new forum instance (admin-only flow).
    /// Pubkeys are 33-byte SEC1-compressed hex strings.
    Q_INVOKABLE void createInstance(const QString& adminAccountId,
                                    int k, int n, int mTotal, int dDepth,
                                    const QString& stakeAmount,
                                    const QString& label,
                                    const QStringList& moderatorPubkeysHex);

    /// Generate a fresh member identity for this Basecamp user-dir. Returns
    /// silently — the resulting commitment shows up via `identityChanged`.
    Q_INVOKABLE void generateIdentity();

    /// Publish the local identity's commitment to the registry, locking the
    /// stake configured by the instance.
    Q_INVOKABLE void registerSelf(const QString& signerAccountId);

    /// Compose & publish a post to Logos Delivery (off-chain). The body is
    /// opaque payload bytes (UTF-8 here, but the protocol doesn't care).
    /// Adds a row to the `posts` feed locally.
    Q_INVOKABLE void publishPost(const QString& body);

    /// As a moderator: build a certificate share for the post at `postIndex`.
    /// `moderatorIndex` is the moderator's 1-indexed position; share secret
    /// must be supplied out-of-band (we read it from the env var
    /// `FORUM_MODERATOR_SHARE_SECRET_HEX`).
    Q_INVOKABLE void issueStrike(int postIndex, int moderatorIndex);

    /// Aggregate the share pool for the given post into a complete cert
    /// (requires ≥ N shares). Adds the cert to the local cert pool.
    Q_INVOKABLE void aggregateCertificate(int postIndex);

    /// Search the cert pool for K-subsets that reconstruct a registered
    /// member. If found, submits the slash on-chain.
    Q_INVOKABLE void runSlashSearch(const QString& signerAccountId,
                                    const QString& recipientAccountId);

    /// Pull the on-chain instance state and refresh QML-bound properties.
    Q_INVOKABLE void refreshState();

    /// Called by QML (or the integration layer) when a delivery_module
    /// `messageReceived` event arrives for one of our topics. Routes the
    /// base64-encoded payload into either the post pool or the cert pool
    /// depending on `contentTopic`.
    Q_INVOKABLE void onIncomingDeliveryMessage(const QString& contentTopic,
                                               const QString& payloadBase64);

    /// Returns the current set of forum topic strings the QML/host should
    /// subscribe to. Two per instance: posts and certificate shares.
    Q_INVOKABLE QStringList contentTopics() const;

signals:
    void programIdHexChanged();
    void stateChanged();
    void identityChanged();
    void busyChanged();
    void lastErrorChanged();
    void lastTxHashChanged();
    void postsChanged();
    void historyChanged();
    void pendingRetriesChanged();
    void txSuccess(const QString& operation, const QString& txHash);
    void txError(const QString& operation, const QString& error);

    /// Emitted when a post envelope (already proof-stamped + share-encrypted)
    /// is ready to broadcast. The QML connects this to its
    /// `logos.callModule("delivery_module", "send", [topic, b64payload])`
    /// when running inside Basecamp; standalone-preview ignores it.
    void postReadyToPublish(const QString& contentTopic, const QString& payloadBase64);
    /// Same for moderation certificate shares.
    void certShareReadyToPublish(const QString& contentTopic, const QString& payloadBase64);

private:
    void dispatchFfi(const QString& operation, std::function<QString()> fn,
                     std::function<void(const QJsonObject&)> onOk = {});
    QJsonObject baseArgs() const;
    void persistIdentity() const;
    void loadIdentity();

    // Logos Delivery integration. Topics are computed deterministically from
    // the program ID: `/logos-forum/1/<program_id_hex_first_16>/posts/v1` etc.
    QString postsTopic() const;
    QString certsTopic() const;
    void publishViaDelivery(const QString& contentTopic, const QString& payloadBase64);
    void setupDeliverySubscription();

    // Environment.
    QString m_walletPath;
    QString m_sequencerUrl;
    QString m_programIdHex;
    QString m_identityPath;       // file where the identity is persisted

    // Instance params (filled by refreshState()).
    QString m_instanceLabel;
    int     m_k = 0, m_n = 0, m_m = 0, m_d = 0;
    QString m_stakeAmount = "0";
    QString m_memberRootHex;
    int     m_memberCount = 0;
    int     m_revocationCount = 0;
    QString m_pooledStake = "0";
    QString m_modPubkeyHex;
    QStringList m_moderatorRoster;
    QVariantList m_revocationList;

    // Local identity (member secret).
    QStringList m_coeffsHex;
    QString     m_commitmentHex;

    // Off-chain state.
    QVariantList m_posts;            // each = {body, msg_id_hex, enc_share, x_hex, y_hex, sharesGathered, complete}
    QVariantList m_completeCerts;
    QVariantList m_history;          // append-only log of strikes, slashes, registrations

    // Plumbing.
    LogosAPI*   m_logosAPI = nullptr;   // owned by Basecamp, may be null in standalone preview
    bool        m_busy = false;
    QString     m_lastError;
    QString     m_lastTxHash;
    QTimer*     m_pollTimer = nullptr;

    // Retry queue: any tx that failed with a transient error is parked here
    // and re-attempted by m_retryTimer. Each entry is {operation, args} as
    // a JSON object — chain ops only (off-chain ops complete locally).
    struct PendingAction {
        QString operation;
        QJsonObject args;
        int attempts = 0;
    };
    std::vector<PendingAction> m_pendingActions;
    QTimer*  m_retryTimer = nullptr;

    void enqueueRetry(const QString& operation, const QJsonObject& args);
    void appendHistory(const QString& kind, const QJsonObject& detail);
    void runRetryPass();
};
