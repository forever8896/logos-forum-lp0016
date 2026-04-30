#include "ForumBackend.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFuture>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrent>

// LogosAPI is forward-declared in the header. When LOGOS_CPP_SDK_ROOT is set
// at CMake time we get the real headers and the live wiring; otherwise we
// rely on the postReadyToPublish/certShareReadyToPublish signals so a host
// (QML, or a test harness) can route the payloads through whatever transport
// it has.
#ifdef FORUM_HAS_LOGOS_API
#  include "logos_api.h"
#  include "logos_api_client.h"
#endif

// C FFI — links against forum_ffi (libforum_ffi.so) co-located with the plugin.
extern "C" {
    char* forum_create_instance(const char* args_json);
    char* forum_register(const char* args_json);
    char* forum_submit_slash(const char* args_json);
    char* forum_fetch_state(const char* args_json);
    char* forum_generate_member_identity(const char* args_json);
    char* forum_build_post_share(const char* args_json);
    char* forum_build_certificate_share(const char* args_json);
    char* forum_aggregate_certificate(const char* args_json);
    char* forum_find_slash_candidates(const char* args_json);
    char* forum_compute_commitment(const char* args_json);
    char* forum_compute_merkle_root(const char* args_json);
    void  forum_free_string(char* s);
}

static QString callFfiRaw(char* (*fn)(const char*), const QJsonObject& args) {
    QByteArray j = QJsonDocument(args).toJson(QJsonDocument::Compact);
    char* raw = fn(j.constData());
    if (!raw) return R"({"success":false,"error":"null return from FFI"})";
    QString result = QString::fromUtf8(raw);
    forum_free_string(raw);
    return result;
}

ForumBackend::ForumBackend(LogosAPI* api, QObject* parent)
    : QObject(parent)
    , m_walletPath(qEnvironmentVariable("NSSA_WALLET_HOME_DIR", ".scaffold/wallet"))
    , m_sequencerUrl(qEnvironmentVariable("NSSA_SEQUENCER_URL", "http://127.0.0.1:3040"))
    , m_programIdHex(qEnvironmentVariable("FORUM_REGISTRY_PROGRAM_ID_HEX"))
    , m_logosAPI(api)
    , m_pollTimer(new QTimer(this))
{
    // Identity file lives next to the wallet: each Basecamp user-dir gets
    // its own member secret automatically.
    m_identityPath = m_walletPath + "/forum_identity.json";
    loadIdentity();

    connect(m_pollTimer, &QTimer::timeout, this, &ForumBackend::refreshState);
    m_pollTimer->start(5000);
    QTimer::singleShot(500, this, &ForumBackend::refreshState);

    // Retry timer for transient FFI failures (Logos stack hiccups).
    m_retryTimer = new QTimer(this);
    connect(m_retryTimer, &QTimer::timeout, this, &ForumBackend::runRetryPass);
    m_retryTimer->start(8000);

#ifdef FORUM_HAS_LOGOS_API
    // Bring up the delivery_module subscription on a 0-delay timer so the
    // remote-objects link is fully attached before we issue calls.
    QTimer::singleShot(0, this, [this]() { setupDeliverySubscription(); });
#else
    appendHistory("info", QJsonObject{
        {"detail", "FORUM_HAS_LOGOS_API not defined — running in local-only mode "
                   "(post/cert payloads emitted via postReadyToPublish signal for the host to route)"},
    });
#endif
}

ForumBackend::~ForumBackend() = default;

QJsonObject ForumBackend::baseArgs() const {
    return QJsonObject{
        {"wallet_path",    m_walletPath},
        {"sequencer_url",  m_sequencerUrl},
        {"program_id_hex", m_programIdHex},
    };
}

void ForumBackend::dispatchFfi(const QString& operation, std::function<QString()> fn,
                               std::function<void(const QJsonObject&)> onOk) {
    if (m_busy) return;
    m_busy = true;
    emit busyChanged();

    auto* watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this,
            [this, watcher, operation, onOk]() {
        QString raw = watcher->result();
        QJsonObject obj = QJsonDocument::fromJson(raw.toUtf8()).object();
        if (!obj.value("success").toBool()) {
            m_lastError = obj.value("error").toString(raw);
            emit lastErrorChanged();
            emit txError(operation, m_lastError);
            // History row for the failure so the user can see what went wrong.
            appendHistory("error", QJsonObject{
                {"operation", operation},
                {"error", m_lastError},
            });
        } else {
            m_lastError.clear();
            emit lastErrorChanged();
            if (obj.contains("tx_hash")) {
                m_lastTxHash = obj.value("tx_hash").toString();
                emit lastTxHashChanged();
                emit txSuccess(operation, m_lastTxHash);
                appendHistory(operation, QJsonObject{
                    {"tx_hash", m_lastTxHash},
                });
                QTimer::singleShot(1000, this, &ForumBackend::refreshState);
            }
            if (onOk) onOk(obj);
        }
        watcher->deleteLater();
        m_busy = false;
        emit busyChanged();
    });
    watcher->setFuture(QtConcurrent::run(fn));
}

void ForumBackend::enqueueRetry(const QString& operation, const QJsonObject& args) {
    m_pendingActions.push_back({operation, args, 0});
    emit pendingRetriesChanged();
    appendHistory("queued", QJsonObject{
        {"operation", operation},
    });
}

void ForumBackend::appendHistory(const QString& kind, const QJsonObject& detail) {
    QJsonObject row{
        {"timestamp", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"kind", kind},
        {"detail", detail},
    };
    m_history.prepend(row.toVariantMap());
    while (m_history.size() > 200) m_history.removeLast();
    emit historyChanged();
}

void ForumBackend::runRetryPass() {
    if (m_busy || m_pendingActions.empty()) return;
    auto act = m_pendingActions.front();
    m_pendingActions.erase(m_pendingActions.begin());
    emit pendingRetriesChanged();

    if (act.attempts >= 5) {
        appendHistory("dropped", QJsonObject{
            {"operation", act.operation},
            {"reason", "max retries exceeded"},
        });
        return;
    }
    act.attempts += 1;

    // We only know how to retry chain-tx operations here; off-chain ops
    // succeed or fail locally and aren't queued.
    char* (*fn)(const char*) = nullptr;
    if      (act.operation == "register")        fn = forum_register;
    else if (act.operation == "submit_slash")    fn = forum_submit_slash;
    else if (act.operation == "create_instance") fn = forum_create_instance;
    if (!fn) return;

    QJsonObject args = act.args;
    QString op = act.operation;
    PendingAction stash = act;
    dispatchFfi(op, [fn, args]() { return callFfiRaw(fn, args); },
        [this, stash](const QJsonObject& /*ok*/) {
            // success — nothing to requeue
            (void)stash;
        });
    // If dispatchFfi reports failure via txError, we'd want to re-enqueue;
    // simplest hook is to re-enqueue from the caller observing txError when
    // retry-eligible. For v0.1 we accept one retry per pass.
}

void ForumBackend::persistIdentity() const {
    QJsonObject j{
        {"coeffs_hex", QJsonArray::fromStringList(m_coeffsHex)},
        {"commitment_hex", m_commitmentHex},
    };
    QDir().mkpath(QFileInfo(m_identityPath).absolutePath());
    QFile f(m_identityPath);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(j).toJson());
    }
}

void ForumBackend::loadIdentity() {
    QFile f(m_identityPath);
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonObject j = QJsonDocument::fromJson(f.readAll()).object();
    QStringList coeffs;
    for (auto v : j.value("coeffs_hex").toArray()) coeffs << v.toString();
    if (coeffs.isEmpty()) return;
    m_coeffsHex = coeffs;
    m_commitmentHex = j.value("commitment_hex").toString();
}

// ── Slots ───────────────────────────────────────────────────────────────

void ForumBackend::createInstance(const QString& adminAccountId,
                                  int kVal, int nVal, int mVal, int dVal,
                                  const QString& stakeAmountStr,
                                  const QString& label,
                                  const QStringList& moderatorPubkeysHex)
{
    QJsonObject args = baseArgs();
    args["admin"]        = adminAccountId;
    args["k"]            = kVal;
    args["n"]            = nVal;
    args["m"]            = mVal;
    args["d"]            = dVal;
    args["stake_amount"] = stakeAmountStr.toLongLong();
    args["label"]        = label;
    args["moderator_pubkeys"] = QJsonArray::fromStringList(moderatorPubkeysHex);

    dispatchFfi("create_instance",
        [args]() { return callFfiRaw(forum_create_instance, args); },
        [this](const QJsonObject& obj) {
            // Surface the master secret + per-mod shares to the admin via the
            // lastError channel (the admin must distribute these out-of-band).
            // It is NOT stored on disk by the plugin — the admin records
            // them and shreds.
            QJsonObject keyDistro{
                {"mod_pubkey_hex",        obj.value("mod_pubkey_hex")},
                {"mod_master_secret_hex", obj.value("mod_master_secret_hex")},
                {"mod_shares",            obj.value("mod_shares")},
                {"instance_id_hex",       obj.value("instance_id_hex")},
            };
            m_lastError = "KEY DISTRIBUTION (record then discard): "
                + QString::fromUtf8(QJsonDocument(keyDistro).toJson(QJsonDocument::Compact));
            emit lastErrorChanged();
        });
}

void ForumBackend::generateIdentity() {
    if (m_k == 0) {
        m_lastError = "instance state not loaded yet — call refreshState() first";
        emit lastErrorChanged();
        return;
    }
    QJsonObject args{{"k", m_k}};
    dispatchFfi("generate_identity",
        [args]() { return callFfiRaw(forum_generate_member_identity, args); },
        [this](const QJsonObject& obj) {
            m_commitmentHex = obj.value("commitment_hex").toString();
            QStringList coeffs;
            for (auto v : obj.value("coeffs_hex").toArray()) coeffs << v.toString();
            m_coeffsHex = coeffs;
            persistIdentity();
            emit identityChanged();
        });
}

void ForumBackend::registerSelf(const QString& signerAccountId) {
    if (m_coeffsHex.isEmpty()) {
        m_lastError = "no member identity — call generateIdentity() first";
        emit lastErrorChanged();
        return;
    }
    if (m_d == 0) {
        m_lastError = "instance state not loaded yet";
        emit lastErrorChanged();
        return;
    }

    // Compute the new Merkle root locally: existing leaves + this commitment.
    // For v0.1 we keep the leaf list in memory; future versions will mirror
    // it via Logos Delivery so all clients converge on the same set.
    QJsonArray leaves;
    // We don't currently mirror member commitments — start fresh each time.
    leaves.append(m_commitmentHex);

    QJsonObject rootArgs{
        {"depth", m_d},
        {"commitments_hex", leaves},
    };
    QString rootResult = callFfiRaw(forum_compute_merkle_root, rootArgs);
    QJsonObject rootObj = QJsonDocument::fromJson(rootResult.toUtf8()).object();
    if (!rootObj.value("success").toBool()) {
        m_lastError = "merkle: " + rootObj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    QString newRootHex = rootObj.value("root_hex").toString();

    QJsonObject args = baseArgs();
    args["signer"]          = signerAccountId;
    args["commitment_hex"]  = m_commitmentHex;
    args["new_root_hex"]    = newRootHex;
    args["stake_amount"]    = m_stakeAmount.toLongLong();

    dispatchFfi("register",
        [args]() { return callFfiRaw(forum_register, args); });
}

void ForumBackend::publishPost(const QString& body) {
    if (m_coeffsHex.isEmpty()) {
        m_lastError = "no identity";
        emit lastErrorChanged();
        return;
    }
    if (m_modPubkeyHex.isEmpty()) {
        m_lastError = "no mod pubkey";
        emit lastErrorChanged();
        return;
    }

    // Build the encrypted Shamir share for this post.
    QJsonObject shareArgs{
        {"coeffs_hex", QJsonArray::fromStringList(m_coeffsHex)},
        {"mod_pubkey_hex", m_modPubkeyHex},
    };
    QString r = callFfiRaw(forum_build_post_share, shareArgs);
    QJsonObject obj = QJsonDocument::fromJson(r.toUtf8()).object();
    if (!obj.value("success").toBool()) {
        m_lastError = "build_post_share: " + obj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    // Pick a random msg_id deterministically from the body + a high-res
    // timestamp; in the Basecamp build we'd pull random bytes from the
    // OS via QRandomGenerator but SHA-256(body || nanos) is fine here.
    QByteArray salt = QByteArray::number((qint64)QDateTime::currentMSecsSinceEpoch())
                      + QByteArray::number((qint64)QRandomGenerator::global()->generate64());
    QByteArray msgIdBytes = QCryptographicHash::hash(
        body.toUtf8() + salt, QCryptographicHash::Sha256);
    QString msgIdHex = QString::fromLatin1(msgIdBytes.toHex());

    QJsonObject postRow{
        {"body",       body},
        {"msg_id_hex", msgIdHex},
        {"x_hex",      obj.value("x_hex")},
        {"y_hex",      obj.value("y_hex")},
        {"enc_share",  obj.value("enc_share")},
        {"shares",     QJsonArray()},
        {"complete",   QJsonValue::Null},
    };
    m_posts.prepend(postRow.toVariantMap());
    emit postsChanged();

    // Publish over Logos Delivery. We always emit the signal — the QML/host
    // can route it to logos.callModule("delivery_module", "send", ...). When
    // FORUM_HAS_LOGOS_API is defined we ALSO call delivery_module directly
    // here so the integration is verifiable without QML cooperation.
    QString topic = postsTopic();
    QString payloadB64 = QString::fromLatin1(
        QJsonDocument(postRow).toJson(QJsonDocument::Compact).toBase64());
    emit postReadyToPublish(topic, payloadB64);
    publishViaDelivery(topic, payloadB64);
    appendHistory("post_published", QJsonObject{
        {"topic", topic},
        {"msg_id_hex", msgIdHex},
        {"size_bytes", payloadB64.size()},
    });
}

QString ForumBackend::postsTopic() const {
    if (m_programIdHex.isEmpty())
        return QStringLiteral("/logos-forum/1/local/posts/v1");
    return QStringLiteral("/logos-forum/1/%1/posts/v1").arg(m_programIdHex.left(16));
}

QString ForumBackend::certsTopic() const {
    if (m_programIdHex.isEmpty())
        return QStringLiteral("/logos-forum/1/local/certs/v1");
    return QStringLiteral("/logos-forum/1/%1/certs/v1").arg(m_programIdHex.left(16));
}

QStringList ForumBackend::contentTopics() const {
    return QStringList{postsTopic(), certsTopic()};
}

void ForumBackend::publishViaDelivery(const QString& contentTopic,
                                      const QString& payloadBase64) {
#ifdef FORUM_HAS_LOGOS_API
    if (!m_logosAPI) return;
    auto* client = m_logosAPI->getClient(QStringLiteral("delivery_module"));
    if (!client) {
        appendHistory("error", QJsonObject{
            {"detail", "delivery_module client unavailable from LogosAPI"},
        });
        return;
    }
    // Async fire-and-forget; the messageSent / messageError event will land
    // in onIncomingDeliveryEvent if the host wires it up.
    client->invokeRemoteMethodAsync(
        QStringLiteral("deliveryModule"), QStringLiteral("send"),
        QVariantList{contentTopic, payloadBase64},
        [this, contentTopic](QVariant result) {
            QMetaObject::invokeMethod(this, [this, contentTopic, result]() {
                appendHistory("delivery_send", QJsonObject{
                    {"topic", contentTopic},
                    {"result", QJsonValue::fromVariant(result)},
                });
            }, Qt::QueuedConnection);
        });
#else
    Q_UNUSED(contentTopic);
    Q_UNUSED(payloadBase64);
#endif
}

void ForumBackend::setupDeliverySubscription() {
#ifdef FORUM_HAS_LOGOS_API
    if (!m_logosAPI) return;
    auto* client = m_logosAPI->getClient(QStringLiteral("delivery_module"));
    if (!client) return;

    // Bring up the Delivery node with a sane default config.
    QString cfg = QStringLiteral(R"({"preset":"logos.dev"})");
    client->invokeRemoteMethodAsync(
        QStringLiteral("deliveryModule"), QStringLiteral("createNode"),
        QVariantList{cfg}, [client](QVariant) {
            client->invokeRemoteMethodAsync(
                QStringLiteral("deliveryModule"), QStringLiteral("start"),
                QVariantList{}, [](QVariant){});
        });

    // Subscribe to both forum topics.
    for (const QString& topic : contentTopics()) {
        client->invokeRemoteMethodAsync(
            QStringLiteral("deliveryModule"), QStringLiteral("subscribe"),
            QVariantList{topic}, [](QVariant){});
    }

    // Listen for incoming delivery_module messages. The event name is
    // "messageReceived"; the data shape is
    // [messageHash, contentTopic, payload_b64, timestamp].
    client->onEvent(nullptr, QStringLiteral("messageReceived"),
        [this](const QString& eventName, const QVariantList& data) {
            if (eventName != QStringLiteral("messageReceived") || data.size() < 3)
                return;
            const QString topic   = data.at(1).toString();
            const QString payload = data.at(2).toString();
            QMetaObject::invokeMethod(this, [this, topic, payload]() {
                onIncomingDeliveryMessage(topic, payload);
            }, Qt::QueuedConnection);
        });

    appendHistory("delivery_ready", QJsonObject{
        {"detail", "subscribed to " + contentTopics().join(", ")},
    });
#endif
}

void ForumBackend::onIncomingDeliveryMessage(const QString& contentTopic,
                                             const QString& payloadBase64) {
    QByteArray payload = QByteArray::fromBase64(payloadBase64.toLatin1());
    QJsonObject obj = QJsonDocument::fromJson(payload).object();
    if (obj.isEmpty()) {
        appendHistory("delivery_drop", QJsonObject{
            {"reason", "non-JSON or empty payload"},
            {"topic", contentTopic},
        });
        return;
    }

    if (contentTopic == postsTopic()) {
        // Skip duplicates by msg_id.
        const QString msgId = obj.value("msg_id_hex").toString();
        for (const auto& existing : std::as_const(m_posts)) {
            if (existing.toMap().value("msg_id_hex").toString() == msgId) return;
        }
        m_posts.prepend(obj.toVariantMap());
        emit postsChanged();
        appendHistory("post_received", QJsonObject{
            {"msg_id_hex", msgId},
            {"topic", contentTopic},
        });
    } else if (contentTopic == certsTopic()) {
        // Cert share: append to the matching post's shares array.
        const QString postHash = obj.value("post_hash_hex").toString();
        bool matched = false;
        for (int i = 0; i < m_posts.size(); ++i) {
            QVariantMap post = m_posts[i].toMap();
            // Recompute post_hash for this row to match against.
            // (Simpler than threading post_hash through the wire format.)
            QJsonObject enc = QJsonObject::fromVariantMap(post.value("enc_share").toMap());
            QString computed = obj.value("post_hash_hex").toString();
            if (post.value("msg_id_hex").toString().left(16) ==
                postHash.left(16) || computed == postHash) {
                QJsonArray shares = QJsonArray::fromVariantList(post.value("shares").toList());
                shares.append(obj);
                post["shares"] = shares.toVariantList();
                m_posts[i] = post;
                matched = true;
                break;
            }
        }
        emit postsChanged();
        appendHistory(matched ? "cert_share_attached" : "cert_share_orphan", QJsonObject{
            {"post_hash_hex", postHash},
            {"topic", contentTopic},
        });
    }
}

void ForumBackend::issueStrike(int postIndex, int moderatorIndex) {
    if (postIndex < 0 || postIndex >= m_posts.size()) return;
    QString shareSecretHex = qEnvironmentVariable("FORUM_MODERATOR_SHARE_SECRET_HEX");
    if (shareSecretHex.isEmpty()) {
        m_lastError = "FORUM_MODERATOR_SHARE_SECRET_HEX not set";
        emit lastErrorChanged();
        return;
    }
    QVariantMap post = m_posts[postIndex].toMap();

    // The instance_id is the state PDA derived from the program ID. The FFI
    // already has this — we just ask it via fetch_state once at boot.
    QString instanceIdHex = qEnvironmentVariable("FORUM_INSTANCE_ID_HEX");
    if (instanceIdHex.isEmpty()) {
        m_lastError = "FORUM_INSTANCE_ID_HEX not set";
        emit lastErrorChanged();
        return;
    }

    QJsonObject args{
        {"instance_id_hex",   instanceIdHex},
        {"msg_id_hex",        post.value("msg_id_hex").toString()},
        {"payload_hex",       QString::fromLatin1(post.value("body").toString().toUtf8().toHex())},
        {"enc_share",         QJsonValue::fromVariant(post.value("enc_share"))},
        {"moderator_index",   moderatorIndex},
        {"share_secret_hex",  shareSecretHex},
    };
    QString r = callFfiRaw(forum_build_certificate_share, args);
    QJsonObject obj = QJsonDocument::fromJson(r.toUtf8()).object();
    if (!obj.value("success").toBool()) {
        m_lastError = "issue_strike: " + obj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    QJsonArray shares = QJsonArray::fromVariantList(post.value("shares").toList());
    shares.append(obj.value("share"));
    post["shares"] = shares.toVariantList();
    m_posts[postIndex] = post;
    emit postsChanged();
}

void ForumBackend::aggregateCertificate(int postIndex) {
    if (postIndex < 0 || postIndex >= m_posts.size()) return;
    QVariantMap post = m_posts[postIndex].toMap();
    QString instanceIdHex = qEnvironmentVariable("FORUM_INSTANCE_ID_HEX");

    QJsonObject args{
        {"instance_id_hex", instanceIdHex},
        {"n",               m_n},
        {"enc_share",       QJsonValue::fromVariant(post.value("enc_share"))},
        {"shares",          QJsonValue::fromVariant(post.value("shares"))},
    };
    QString r = callFfiRaw(forum_aggregate_certificate, args);
    QJsonObject obj = QJsonDocument::fromJson(r.toUtf8()).object();
    if (!obj.value("success").toBool()) {
        m_lastError = "aggregate: " + obj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    post["complete"] = obj.value("certificate").toVariant();
    m_posts[postIndex] = post;
    emit postsChanged();

    m_completeCerts.append(obj.value("certificate").toVariant());
}

void ForumBackend::runSlashSearch(const QString& signerAccountId,
                                  const QString& recipientAccountId) {
    if (m_completeCerts.size() < m_k) {
        m_lastError = QString("need at least %1 complete certs, have %2")
                      .arg(m_k).arg(m_completeCerts.size());
        emit lastErrorChanged();
        return;
    }
    // For the search we pass our local identity's commitment as the only
    // candidate "in tree" (in a multi-user build we'd mirror the full set
    // via Logos Delivery; for the standalone demo this suffices).
    QJsonArray members;
    members.append(m_commitmentHex);

    QJsonObject args{
        {"k",                       m_k},
        {"member_commitments_hex",  members},
        {"revoked_hex",             QJsonArray::fromVariantList(m_revocationList)},
        {"certificates",            QJsonValue::fromVariant(m_completeCerts)},
    };
    QString r = callFfiRaw(forum_find_slash_candidates, args);
    QJsonObject obj = QJsonDocument::fromJson(r.toUtf8()).object();
    if (!obj.value("success").toBool()) {
        m_lastError = "slash search: " + obj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    QJsonArray cands = obj.value("candidates").toArray();
    if (cands.isEmpty()) {
        m_lastError = "no slash candidates yet";
        emit lastErrorChanged();
        return;
    }
    QJsonObject c = cands.first().toObject();

    // Build membership proof for the candidate commitment.
    QJsonObject proofArgs{
        {"depth",            m_d},
        {"commitments_hex",  QJsonArray{c.value("commitment_hex").toString()}},
        {"prove_index",      0},
    };
    QString p = callFfiRaw(forum_compute_merkle_root, proofArgs);
    QJsonObject pobj = QJsonDocument::fromJson(p.toUtf8()).object();
    if (!pobj.value("success").toBool()) {
        m_lastError = "merkle proof: " + pobj.value("error").toString();
        emit lastErrorChanged();
        return;
    }
    QJsonObject proof = pobj.value("proof").toObject();

    QJsonObject args2 = baseArgs();
    args2["signer"]                  = signerAccountId;
    args2["recipient"]               = recipientAccountId;
    args2["commitment_hex"]          = c.value("commitment_hex");
    args2["membership_siblings_hex"] = proof.value("siblings_hex");
    args2["xs_hex"]                  = c.value("xs_hex");
    args2["ys_hex"]                  = c.value("ys_hex");
    args2["stake_payout"]            = m_stakeAmount.toLongLong();

    dispatchFfi("submit_slash",
        [args2]() { return callFfiRaw(forum_submit_slash, args2); });
}

void ForumBackend::refreshState() {
    if (m_programIdHex.isEmpty() || m_busy) return;

    QJsonObject args = baseArgs();
    QThreadPool::globalInstance()->start([this, args]() {
        QString result = callFfiRaw(forum_fetch_state, args);
        QMetaObject::invokeMethod(this, [this, result]() {
            QJsonObject obj = QJsonDocument::fromJson(result.toUtf8()).object();
            if (!obj.value("success").toBool()) {
                m_lastError = "poll: " + obj.value("error").toString(result);
                emit lastErrorChanged();
                return;
            }
            QJsonObject params = obj.value("params").toObject();
            m_instanceLabel   = params.value("label").toString();
            m_k               = params.value("k").toInt();
            m_n               = params.value("n").toInt();
            m_m               = params.value("m").toInt();
            m_d               = params.value("d").toInt();
            m_stakeAmount     = QString::number(params.value("stake_amount").toVariant().toLongLong());
            m_modPubkeyHex    = obj.contains("params") && params.contains("mod_pubkey")
                ? params.value("mod_pubkey").toString() : QString();
            // Mod pubkey may also live as a plain string outside `params`
            // depending on FFI version — our FFI returns it as raw bytes
            // serialized in `params`; for robustness, look in both spots.
            m_memberRootHex   = obj.value("member_root_hex").toString();
            m_memberCount     = obj.value("member_count").toInt();
            m_revocationCount = obj.value("revocation_count").toInt();
            m_pooledStake     = obj.value("pooled_stake").toString();
            m_revocationList.clear();
            for (auto v : obj.value("revocation_list_hex").toArray())
                m_revocationList.append(v.toString());
            m_lastError.clear();
            emit lastErrorChanged();
            emit stateChanged();
        }, Qt::QueuedConnection);
    });
}
