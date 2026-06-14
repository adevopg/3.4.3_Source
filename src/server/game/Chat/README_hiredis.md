Hiredis integration for ChatBridge

This project includes optional direct Redis publishing via hiredis.

To enable:
1) Build and install hiredis for Windows and make the include/lib available to Visual Studio.
   - You can build hiredis using CMake and then open the generated solution or build via msbuild.
2) Add the include path and link against hiredis.lib in your game server project.
3) Define USE_HIREDIS in project preprocessor definitions for the files under src/server/game/Chat.

Behavior:
- When USE_HIREDIS is defined ChatBridge will attempt to connect to 127.0.0.1:6379 and PUBLISH messages to the specified channel.
- Otherwise ChatBridge falls back to using the environment variable REDIS_PUBLISH_CMD to run redis-cli or logs the message if not configured.

Notes:
- This is a minimal synchronous publisher for prototyping. For production, consider an async connection and reconnect logic.
