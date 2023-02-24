# Minetest Solar Crypto SDK
A Solar Crypto SDK that enables wallet generation and BIP340 message signing in Minetest.

### Dependencies
- Minetest 5.6.1
- Libtorsion https://github.com/bcoin-org/libtorsion
- BCL https://github.com/nayuki/Bitcoin-Cryptography-Library

Tested with Ubuntu 22.04.

### Installation
First, get yourself a running copy of Minetest. The Solar Crypto SDK might work with other Minetest versions however it
is tested with version 5.6.1. I used the `stable-5` branch of https://github.com/minetest/minetest.git.

Next, after you got a barebone Minetest client running, proceed with the following steps to install the Solar Crypto SDK:

1. Clone the Solar Crypto SDK in the Minetest library folder by `cd minetest/lib` and or `git clone git@github.com:e-m-s-y/minetest_solar_crypto_sdk.git solar_crypto`.
2. Move the `l_solar_crypto.cpp` and `l_solar_crypto.h` files to `minetest/src/script/lua_api`.
3. Add `${CMAKE_CURRENT_SOURCE_DIR}/l_solar_crypto.cpp` to `common_SCRIPT_LUA_API_SRCS` in `minetest/src/script/lua_api/CMakeLists.txt`. I added it right after `l_settings.cpp` to follow the alphabetical order.
4. Extend Minetest core by adding the lines prefixed with a `+` to `minetest/src/script/lua_api/l_util.cpp`. Remove the `+` symbols in your code.

Include the Solar Crypto header file:
```
#include "lua_api/l_settings.h"
+#include "lua_api/l_solar_crypto.h"
#include "common/c_converter.h"
```
Add these lines to the bottom of functions `ModApiUtil::Initialize`, `ModApiUtil::InitializeClient` and `ModApiUtil::InitializeAsync`.
```
LuaSettings::create(L, g_settings, g_settings_path);
lua_setfield(L, top, "settings");
+
+LuaCrypto::create(L);
+lua_setfield(L, top, "solar_crypto");
```

5. Add `${SOLAR_CRYPTO_INCLUDE_DIR}` to `include_directories` in `minetest/src/CMakeLists.txt`. I added it right after `${LUA_BIT_INCLUDE_DIR}`.
6. Add `${SOLAR_CRYPTO_LIBRARY}` to `target_link_libraries` inside if `BUILD_CLIENT` statement in `minetest/src/CMakeLists.txt`. I added it right
   after `${PLATFORM_LIBS}`.
7. Optional: If you want to enable the Solar Crypto SDK for Server builds as well then add `${SOLAR_CRYPTO_LIBRARY}` to `target_link_libraries` inside if `BUILD_SERVER` right after `${PLATFORM_LIBS}`.
8. Add these lines to `minetest/CMakeLists.txt` right before `find_package(GMP REQUIRED)`:
```
+set(SOLAR_CRYPTO_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/solar_crypto)
+set(SOLAR_CRYPTO_LIBRARY solar_crypto)
+add_subdirectory(lib/solar_crypto)
+
# Library pack
find_package(GMP REQUIRED)
```

Installation is complete.

Tip: replace the line below in `create_world_formspec` function of `dlg_create_world.lua` in order to test if it works properly.
```
fgettext("World name") ..
-";" .. core.formspec_escape(dialogdata.worldname) .. "]" ..
+";" .. core.solar_crypto.generate_wallet().address .. "]" ..
```
After building it should show a random wallet address in the World Name field after clicking the New button in Start Game tab.

### Usage
```
local wallet = core.solar_crypto.generate_wallet()

-- wallet.address
-- wallet.mnemonic
-- wallet.publicKey

local text = "Hello World"
local message = core.solar_crypto.sign_message(text, wallet.mnemonic)

-- message.signature
-- message.text
```

### Running the client
Make sure to cd to your minetest root directory. Compile and build the client using the command below.

`cmake . -DRUN_IN_PLACE=TRUE -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) && ./bin/minetest`.

### TODO
- Clean up dependencies (use dependency manager).
- Add sign transaction feature.
- Add crypto debug dialog.
