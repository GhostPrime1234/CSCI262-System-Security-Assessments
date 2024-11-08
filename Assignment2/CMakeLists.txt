cmake_minimum_required(VERSION 3.29)
project(Assignment2)

set(CMAKE_CXX_STANDARD 14)

include_directories(matplotlib-cpp-master)
include_directories(SFML-2.6.1/examples/shader)
include_directories(SFML-2.6.1/include)
include_directories(SFML-2.6.1/include/SFML)
include_directories(SFML-2.6.1/include/SFML/Audio)
include_directories(SFML-2.6.1/include/SFML/Graphics)
include_directories(SFML-2.6.1/include/SFML/Network)
include_directories(SFML-2.6.1/include/SFML/System)
include_directories(SFML-2.6.1/include/SFML/Window)

add_executable(Assignment2
    matplotlib-cpp-master/examples/animation.cpp
    matplotlib-cpp-master/examples/bar.cpp
    matplotlib-cpp-master/examples/basic.cpp
    matplotlib-cpp-master/examples/colorbar.cpp
    matplotlib-cpp-master/examples/contour.cpp
    matplotlib-cpp-master/examples/fill.cpp
    matplotlib-cpp-master/examples/fill_inbetween.cpp
    matplotlib-cpp-master/examples/imshow.cpp
    matplotlib-cpp-master/examples/lines3d.cpp
    matplotlib-cpp-master/examples/minimal.cpp
    matplotlib-cpp-master/examples/modern.cpp
    matplotlib-cpp-master/examples/nonblock.cpp
    matplotlib-cpp-master/examples/quiver.cpp
    matplotlib-cpp-master/examples/spy.cpp
    matplotlib-cpp-master/examples/subplot.cpp
    matplotlib-cpp-master/examples/subplot2grid.cpp
    matplotlib-cpp-master/examples/surface.cpp
    matplotlib-cpp-master/examples/update.cpp
    matplotlib-cpp-master/examples/xkcd.cpp
    matplotlib-cpp-master/matplotlibcpp.h
    SFML-2.6.1/examples/ftp/Ftp.cpp
    SFML-2.6.1/examples/island/Island.cpp
    SFML-2.6.1/examples/joystick/Joystick.cpp
    SFML-2.6.1/examples/opengl/OpenGL.cpp
    SFML-2.6.1/examples/shader/Effect.hpp
    SFML-2.6.1/examples/shader/Shader.cpp
    SFML-2.6.1/examples/sockets/Sockets.cpp
    SFML-2.6.1/examples/sockets/TCP.cpp
    SFML-2.6.1/examples/sockets/UDP.cpp
    SFML-2.6.1/examples/sound/Sound.cpp
    SFML-2.6.1/examples/sound_capture/SoundCapture.cpp
    SFML-2.6.1/examples/tennis/Tennis.cpp
    SFML-2.6.1/examples/voip/Client.cpp
    SFML-2.6.1/examples/voip/Server.cpp
    SFML-2.6.1/examples/voip/VoIP.cpp
    SFML-2.6.1/examples/vulkan/Vulkan.cpp
    SFML-2.6.1/examples/win32/Win32.cpp
    SFML-2.6.1/examples/window/Window.cpp
    SFML-2.6.1/include/SFML/Audio/AlResource.hpp
    SFML-2.6.1/include/SFML/Audio/Export.hpp
    SFML-2.6.1/include/SFML/Audio/InputSoundFile.hpp
    SFML-2.6.1/include/SFML/Audio/Listener.hpp
    SFML-2.6.1/include/SFML/Audio/Music.hpp
    SFML-2.6.1/include/SFML/Audio/OutputSoundFile.hpp
    SFML-2.6.1/include/SFML/Audio/Sound.hpp
    SFML-2.6.1/include/SFML/Audio/SoundBuffer.hpp
    SFML-2.6.1/include/SFML/Audio/SoundBufferRecorder.hpp
    SFML-2.6.1/include/SFML/Audio/SoundFileFactory.hpp
    SFML-2.6.1/include/SFML/Audio/SoundFileFactory.inl
    SFML-2.6.1/include/SFML/Audio/SoundFileReader.hpp
    SFML-2.6.1/include/SFML/Audio/SoundFileWriter.hpp
    SFML-2.6.1/include/SFML/Audio/SoundRecorder.hpp
    SFML-2.6.1/include/SFML/Audio/SoundSource.hpp
    SFML-2.6.1/include/SFML/Audio/SoundStream.hpp
    SFML-2.6.1/include/SFML/Graphics/BlendMode.hpp
    SFML-2.6.1/include/SFML/Graphics/CircleShape.hpp
    SFML-2.6.1/include/SFML/Graphics/Color.hpp
    SFML-2.6.1/include/SFML/Graphics/ConvexShape.hpp
    SFML-2.6.1/include/SFML/Graphics/Drawable.hpp
    SFML-2.6.1/include/SFML/Graphics/Export.hpp
    SFML-2.6.1/include/SFML/Graphics/Font.hpp
    SFML-2.6.1/include/SFML/Graphics/Glsl.hpp
    SFML-2.6.1/include/SFML/Graphics/Glsl.inl
    SFML-2.6.1/include/SFML/Graphics/Glyph.hpp
    SFML-2.6.1/include/SFML/Graphics/Image.hpp
    SFML-2.6.1/include/SFML/Graphics/PrimitiveType.hpp
    SFML-2.6.1/include/SFML/Graphics/Rect.hpp
    SFML-2.6.1/include/SFML/Graphics/Rect.inl
    SFML-2.6.1/include/SFML/Graphics/RectangleShape.hpp
    SFML-2.6.1/include/SFML/Graphics/RenderStates.hpp
    SFML-2.6.1/include/SFML/Graphics/RenderTarget.hpp
    SFML-2.6.1/include/SFML/Graphics/RenderTexture.hpp
    SFML-2.6.1/include/SFML/Graphics/RenderWindow.hpp
    SFML-2.6.1/include/SFML/Graphics/Shader.hpp
    SFML-2.6.1/include/SFML/Graphics/Shape.hpp
    SFML-2.6.1/include/SFML/Graphics/Sprite.hpp
    SFML-2.6.1/include/SFML/Graphics/Text.hpp
    SFML-2.6.1/include/SFML/Graphics/Texture.hpp
    SFML-2.6.1/include/SFML/Graphics/Transform.hpp
    SFML-2.6.1/include/SFML/Graphics/Transformable.hpp
    SFML-2.6.1/include/SFML/Graphics/Vertex.hpp
    SFML-2.6.1/include/SFML/Graphics/VertexArray.hpp
    SFML-2.6.1/include/SFML/Graphics/VertexBuffer.hpp
    SFML-2.6.1/include/SFML/Graphics/View.hpp
    SFML-2.6.1/include/SFML/Network/Export.hpp
    SFML-2.6.1/include/SFML/Network/Ftp.hpp
    SFML-2.6.1/include/SFML/Network/Http.hpp
    SFML-2.6.1/include/SFML/Network/IpAddress.hpp
    SFML-2.6.1/include/SFML/Network/Packet.hpp
    SFML-2.6.1/include/SFML/Network/Socket.hpp
    SFML-2.6.1/include/SFML/Network/SocketHandle.hpp
    SFML-2.6.1/include/SFML/Network/SocketSelector.hpp
    SFML-2.6.1/include/SFML/Network/TcpListener.hpp
    SFML-2.6.1/include/SFML/Network/TcpSocket.hpp
    SFML-2.6.1/include/SFML/Network/UdpSocket.hpp
    SFML-2.6.1/include/SFML/System/Clock.hpp
    SFML-2.6.1/include/SFML/System/Err.hpp
    SFML-2.6.1/include/SFML/System/Export.hpp
    SFML-2.6.1/include/SFML/System/FileInputStream.hpp
    SFML-2.6.1/include/SFML/System/InputStream.hpp
    SFML-2.6.1/include/SFML/System/Lock.hpp
    SFML-2.6.1/include/SFML/System/MemoryInputStream.hpp
    SFML-2.6.1/include/SFML/System/Mutex.hpp
    SFML-2.6.1/include/SFML/System/NativeActivity.hpp
    SFML-2.6.1/include/SFML/System/NonCopyable.hpp
    SFML-2.6.1/include/SFML/System/Sleep.hpp
    SFML-2.6.1/include/SFML/System/String.hpp
    SFML-2.6.1/include/SFML/System/String.inl
    SFML-2.6.1/include/SFML/System/Thread.hpp
    SFML-2.6.1/include/SFML/System/Thread.inl
    SFML-2.6.1/include/SFML/System/ThreadLocal.hpp
    SFML-2.6.1/include/SFML/System/ThreadLocalPtr.hpp
    SFML-2.6.1/include/SFML/System/ThreadLocalPtr.inl
    SFML-2.6.1/include/SFML/System/Time.hpp
    SFML-2.6.1/include/SFML/System/Utf.hpp
    SFML-2.6.1/include/SFML/System/Utf.inl
    SFML-2.6.1/include/SFML/System/Vector2.hpp
    SFML-2.6.1/include/SFML/System/Vector2.inl
    SFML-2.6.1/include/SFML/System/Vector3.hpp
    SFML-2.6.1/include/SFML/System/Vector3.inl
    SFML-2.6.1/include/SFML/Window/Clipboard.hpp
    SFML-2.6.1/include/SFML/Window/Context.hpp
    SFML-2.6.1/include/SFML/Window/ContextSettings.hpp
    SFML-2.6.1/include/SFML/Window/Cursor.hpp
    SFML-2.6.1/include/SFML/Window/Event.hpp
    SFML-2.6.1/include/SFML/Window/Export.hpp
    SFML-2.6.1/include/SFML/Window/GlResource.hpp
    SFML-2.6.1/include/SFML/Window/Joystick.hpp
    SFML-2.6.1/include/SFML/Window/Keyboard.hpp
    SFML-2.6.1/include/SFML/Window/Mouse.hpp
    SFML-2.6.1/include/SFML/Window/Sensor.hpp
    SFML-2.6.1/include/SFML/Window/Touch.hpp
    SFML-2.6.1/include/SFML/Window/VideoMode.hpp
    SFML-2.6.1/include/SFML/Window/Vulkan.hpp
    SFML-2.6.1/include/SFML/Window/Window.hpp
    SFML-2.6.1/include/SFML/Window/WindowBase.hpp
    SFML-2.6.1/include/SFML/Window/WindowHandle.hpp
    SFML-2.6.1/include/SFML/Window/WindowStyle.hpp
    SFML-2.6.1/include/SFML/Audio.hpp
    SFML-2.6.1/include/SFML/Config.hpp
    SFML-2.6.1/include/SFML/GpuPreference.hpp
    SFML-2.6.1/include/SFML/Graphics.hpp
    SFML-2.6.1/include/SFML/Main.hpp
    SFML-2.6.1/include/SFML/Network.hpp
    SFML-2.6.1/include/SFML/OpenGL.hpp
    SFML-2.6.1/include/SFML/System.hpp
    SFML-2.6.1/include/SFML/Window.hpp
    main.cpp)
