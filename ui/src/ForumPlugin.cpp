#include "ForumPlugin.h"
#include "ForumBackend.h"

#include <QQmlContext>
#include <QQmlEngine>
#include <QQuickWidget>
#include <QUrl>
#include <cstdlib>

ForumPlugin::ForumPlugin(QObject* parent) : QObject(parent) {}
ForumPlugin::~ForumPlugin() = default;

void ForumPlugin::initLogos(LogosAPI* api) {
    m_api = api;
}

QWidget* ForumPlugin::createWidget(LogosAPI* api) {
    if (api) m_api = api;

    if (!m_backend)
        m_backend = new ForumBackend(m_api, this);

    auto* view = new QQuickWidget();
    view->engine()->rootContext()->setContextProperty("backend", m_backend);
    view->setResizeMode(QQuickWidget::SizeRootObjectToView);

    // For dev: set QML_PATH to ui/qml so iterating on Main.qml doesn't
    // require a rebuild. In a packaged plugin we read from the qrc.
    const char* qmlPath = std::getenv("QML_PATH");
    if (qmlPath) {
        view->setSource(QUrl::fromLocalFile(
            QString::fromUtf8(qmlPath) + "/Main.qml"));
    } else {
        view->setSource(QUrl("qrc:/qml/Main.qml"));
    }
    return view;
}

void ForumPlugin::destroyWidget(QWidget* widget) {
    delete m_backend;
    m_backend = nullptr;
    delete widget;
}
