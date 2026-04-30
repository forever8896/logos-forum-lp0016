// Standalone test harness — loads ForumPlugin directly without Basecamp.
// Usage:
//   QML_PATH=ui/qml ./forum_app
//   FORUM_REGISTRY_PROGRAM_ID_HEX=<64-hex> NSSA_WALLET_HOME_DIR=.scaffold/wallet \
//     QML_PATH=ui/qml ./forum_app

#include "ForumPlugin.h"

#include <QApplication>
#include <QMainWindow>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("LogosForum");
    app.setApplicationVersion("0.1.0");

    ForumPlugin plugin;

    QMainWindow window;
    window.setWindowTitle("Logos Forum — Basecamp module preview");
    window.resize(900, 700);

    QWidget* view = plugin.createWidget(nullptr);
    window.setCentralWidget(view);
    window.show();

    return app.exec();
}
