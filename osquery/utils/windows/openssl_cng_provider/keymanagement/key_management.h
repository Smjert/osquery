#pragma once

#include <openssl/types.h>

extern "C" {
const OSSL_ALGORITHM* OsqueryGetKeyManagementAlgorithms();
void* OsqueryCNGKeyManagementDup(const void* keydata_from, int selection);
}
