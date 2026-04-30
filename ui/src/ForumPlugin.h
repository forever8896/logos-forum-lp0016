#pragma once

#include <QObject>
#include <QWidget>
#include <QtPlugin>

class LogosAPI;
class ForumBackend;

// Backward-compatible plugin interface for the current Basecamp plugin loader.
// We mirror whisper-wall's vendored declaration so the plugin loads under both
// the standalone Qt build and inside Basecamp.
class IComponent {
public:
    virtual ~IComponent() = default;
    virtual QWidget* createWidget(LogosAPI* api = nullptr) = 0;
    virtual void     destroyWidget(QWidget* widget) = 0;
};
#define IComponent_iid "com.logos.component.IComponent"
Q_DECLARE_INTERFACE(IComponent, IComponent_iid)

class ForumPlugin : public QObject, public IComponent {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID IComponent_iid FILE "../metadata.json")
    Q_INTERFACES(IComponent)

public:
    explicit ForumPlugin(QObject* parent = nullptr);
    ~ForumPlugin() override;

    // Called by Basecamp before createWidget() to hand us the LogosAPI.
    Q_INVOKABLE void initLogos(LogosAPI* api);

    QWidget* createWidget(LogosAPI* api = nullptr) override;
    void     destroyWidget(QWidget* widget) override;

private:
    LogosAPI*     m_api     = nullptr;
    ForumBackend* m_backend = nullptr;
};
