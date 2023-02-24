#include <iostream>
#include <solar/crypto.h>

#include "lua_api/l_solar_crypto.h"
#include "lua_api/l_internal.h"
#include "threading/mutex_auto_lock.h"

LuaCrypto::LuaCrypto(){}

LuaCrypto::~LuaCrypto(){}

void LuaCrypto::create(lua_State *L)
{
	LuaCrypto *o = new LuaCrypto();
	*(void **)(lua_newuserdata(L, sizeof(void *))) = o;
	luaL_getmetatable(L, className);
	lua_setmetatable(L, -2);
}

int LuaCrypto::l_generate_wallet(lua_State *L)
{
	lua_newtable(L);

	std::string mnemonic = generate_mnemonic(128);

	lua_pushstring(L, "address");
	lua_pushstring(L, mnemonic_to_wallet_address(mnemonic).c_str());
	lua_settable(L, -3);

	lua_pushstring(L, "public_key");
	lua_pushstring(L, mnemonic_to_public_key(mnemonic).c_str());
	lua_settable(L, -3);

	lua_pushstring(L, "mnemonic");
	lua_pushstring(L, mnemonic.c_str());
	lua_settable(L, -3);

	return 1;
}

int LuaCrypto::l_sign_message(lua_State *L)
{
	std::string message = std::string(luaL_checkstring(L, 2));
	std::string mnemonic = std::string(luaL_checkstring(L, 3));

	lua_newtable(L);

	lua_pushstring(L, "signature");
	lua_pushstring(L, sign_message(mnemonic, message).c_str());
	lua_settable(L, -3);

	lua_pushstring(L, "text");
	lua_pushstring(L, message.c_str());
	lua_settable(L, -3);

	return 1;
}

// Garbage collector
int LuaCrypto::gc_object(lua_State* L)
{
	LuaCrypto* o = *(LuaCrypto **)(lua_touserdata(L, 1));
	delete o;
	return 0;
}

void LuaCrypto::Register(lua_State* L)
{
	lua_newtable(L);
	int methodtable = lua_gettop(L);
	luaL_newmetatable(L, className);
	int metatable = lua_gettop(L);

	lua_pushliteral(L, "__metatable");
	lua_pushvalue(L, methodtable);
	lua_settable(L, metatable);

	lua_pushliteral(L, "__index");
	lua_pushvalue(L, methodtable);
	lua_settable(L, metatable);

	lua_pushliteral(L, "__gc");
	lua_pushcfunction(L, gc_object);
	lua_settable(L, metatable);

	lua_pop(L, 1);

	luaL_register(L, nullptr, methods);
	lua_pop(L, 1);

	lua_register(L, className, create_object);
}

int LuaCrypto::create_object(lua_State* L)
{
	NO_MAP_LOCK_REQUIRED;
	LuaCrypto* o = new LuaCrypto();
	*(void **)(lua_newuserdata(L, sizeof(void *))) = o;
	luaL_getmetatable(L, className);
	lua_setmetatable(L, -2);
	return 1;
}

LuaCrypto* LuaCrypto::checkobject(lua_State* L, int narg)
{
	NO_MAP_LOCK_REQUIRED;
	luaL_checktype(L, narg, LUA_TUSERDATA);
	void *ud = luaL_checkudata(L, narg, className);
	if (!ud)
		luaL_typerror(L, narg, className);
	return *(LuaCrypto**) ud;
}

const char LuaCrypto::className[] = "Crypto";
const luaL_Reg LuaCrypto::methods[] = {
	luamethod(LuaCrypto, generate_wallet),
	luamethod(LuaCrypto, sign_message),
	{0,0}
};
