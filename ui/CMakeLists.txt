cmake_minimum_required(VERSION 3.20)
project(forum-ui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Framework build (logos-module-builder) ────────────────────────────────────
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)

    logos_module(
        NAME forum_ui
        SOURCES
            src/ForumPlugin.h
            src/ForumPlugin.cpp
            src/ForumBackend.h
            src/ForumBackend.cpp
        EXTERNAL_LIBS forum_ffi
    )

# ── Manual build (development / standalone) ───────────────────────────────────
else()
    set(CMAKE_AUTOMOC ON)

    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Quick QuickWidgets Qml Concurrent)

    # Location of the compiled Rust cdylib (build with: cargo build --release in ui/ffi/).
    if(DEFINED ENV{FORUM_FFI_LIB_DIR})
        set(FORUM_FFI_LIB_DIR "$ENV{FORUM_FFI_LIB_DIR}")
    elseif(NOT DEFINED FORUM_FFI_LIB_DIR)
        set(FORUM_FFI_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ffi/target/release")
    endif()

    set(PLUGIN_TARGET forum_ui_plugin)

    qt_add_plugin(${PLUGIN_TARGET} CLASS_NAME ForumPlugin)

    target_sources(${PLUGIN_TARGET} PRIVATE
        src/ForumPlugin.cpp
        src/ForumBackend.cpp
    )

    qt_add_resources(${PLUGIN_TARGET} "forum_ui_qml"
        PREFIX "/qml"
        BASE "qml"
        FILES qml/Main.qml
    )

    if(DEFINED ENV{LOGOS_CPP_SDK_ROOT})
        set(LOGOS_CPP_SDK_ROOT "$ENV{LOGOS_CPP_SDK_ROOT}")
    endif()

    target_include_directories(${PLUGIN_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    if(LOGOS_CPP_SDK_ROOT)
        target_include_directories(${PLUGIN_TARGET} PRIVATE
            ${LOGOS_CPP_SDK_ROOT}/include
            ${LOGOS_CPP_SDK_ROOT}/include/cpp
            ${LOGOS_CPP_SDK_ROOT}/include/core
            ${LOGOS_CPP_SDK_ROOT}/cpp
        )
        # Activates the live delivery_module / storage_module wiring in
        # ForumBackend. Without it, the backend keeps posts in a local list
        # and emits postReadyToPublish for any external consumer to handle.
        target_compile_definitions(${PLUGIN_TARGET} PRIVATE FORUM_HAS_LOGOS_API)
    endif()

    target_link_directories(${PLUGIN_TARGET} PRIVATE "${FORUM_FFI_LIB_DIR}")

    target_link_libraries(${PLUGIN_TARGET} PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Quick Qt6::QuickWidgets
        Qt6::Qml Qt6::Concurrent
        forum_ffi
    )

    if(APPLE)
        set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH   "@loader_path"
            INSTALL_RPATH "@loader_path"
        )
    elseif(UNIX)
        set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH   "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
        )
    endif()

    install(TARGETS ${PLUGIN_TARGET} LIBRARY DESTINATION lib)
    install(FILES "${FORUM_FFI_LIB_DIR}/libforum_ffi.so" DESTINATION lib)

    # ── Standalone preview app ────────────────────────────────────────────────
    set(APP_TARGET forum_app)

    qt_add_executable(${APP_TARGET} src/main.cpp
        src/ForumPlugin.cpp
        src/ForumBackend.cpp
    )

    qt_add_resources(${APP_TARGET} "forum_app_qml"
        PREFIX "/qml"
        BASE "qml"
        FILES qml/Main.qml
    )

    target_include_directories(${APP_TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    if(LOGOS_CPP_SDK_ROOT)
        target_include_directories(${APP_TARGET} PRIVATE
            ${LOGOS_CPP_SDK_ROOT}/include
            ${LOGOS_CPP_SDK_ROOT}/include/cpp
            ${LOGOS_CPP_SDK_ROOT}/include/core
            ${LOGOS_CPP_SDK_ROOT}/cpp
        )
        target_compile_definitions(${APP_TARGET} PRIVATE FORUM_HAS_LOGOS_API)
    endif()

    target_link_directories(${APP_TARGET} PRIVATE "${FORUM_FFI_LIB_DIR}")

    target_link_libraries(${APP_TARGET} PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Quick Qt6::QuickWidgets
        Qt6::Qml Qt6::Concurrent
        forum_ffi
    )

    if(APPLE)
        set_target_properties(${APP_TARGET} PROPERTIES
            BUILD_RPATH   "@loader_path"
            INSTALL_RPATH "@loader_path"
        )
    elseif(UNIX)
        set_target_properties(${APP_TARGET} PROPERTIES
            BUILD_RPATH   "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
        )
    endif()

    install(TARGETS ${APP_TARGET} RUNTIME DESTINATION bin)
endif()
