#pragma once

namespace osquery {
constexpr char* algorithm_properties = "provider=cng_provider,fips=0";

using OSSLCNGFunctionPtr = void (*)();
} // namespace cng
