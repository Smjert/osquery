# thrift library build notes

Keep a build of the osquery `openssl` target ready, one for each architecture and platform, since it will need to be used to properly configure Thrift.

Prepare a directory with the boost headers in the install structure, which should create a `include` directory toplevel, which is supposed to be saved into the env var `BOOST_HEADERS`.
The structure of the folder can be obtained with the following script, after having moved inside of it:
```sh
#!/bin/bash
mkdir -p include/boost
libs=$(find <osquery source path>/libraries/cmake/source/boost/src/libs -mindepth 1 -maxdepth 1)

for lib in $libs; do
  if ! [ -d "$lib/include/boost" ]; then
    continue
  fi

  rsync -av "$lib/include/boost/"* include/boost

done
```

This can be then used on all platforms.

## Linux

Integrate the osquery-toolchain; you can use the `cmake/toolchain.cmake` as a reference.

```sh
cmake \
  -S . \
  -B b \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -G Ninja \
  -DBoost_USE_STATIC_LIBS=ON \
  -DBoost_INCLUDE_DIR=/path/to/osquery/libraries/cmake/source/boost/src/libs/config/include/ \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_OPENSSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_LIBEVENT=OFF \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain
```

## macOS

### macOS x86_64

```sh
export OSQUERY_SRC="<osquery source directory>"
export OSQUERY_BUILD="<osquery build directory>"

cmake \
  -S . \
  -B b \
  -DBUILD_SHARED_LIBS=OFF \
  -DBoost_USE_STATIC_LIBS=ON \
  -DBoost_INCLUDE_DIR=${BOOST_HEADERS} \
  -DWITH_OPENSSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_LIBEVENT=OFF \
  -DBUILD_COMPILER=OFF \
  -DBUILD_C_GLIB=OFF \
  -DBUILD_JAVA=OFF \
  -DBUILD_JAVASCRIPT=OFF \
  -DBUILD_NODEJS=OFF \
  -DBUILD_KOTLIN=OFF \
  -DBUILD_PYTHON=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DOPENSSL_ROOT_DIR=${OSQUERY_BUILD}/installed_formulas/openssl
```

### macOS ARM (M1, M2, etc.)

```sh
export OSQUERY_SRC="<osquery source directory>"
export OSQUERY_BUILD="<osquery build directory>"

cmake \
  -S . \
  -B b \
  -DBUILD_SHARED_LIBS=OFF \
  -DBoost_USE_STATIC_LIBS=ON \
  -DBoost_INCLUDE_DIR=${BOOST_HEADERS} \
  -DWITH_OPENSSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_LIBEVENT=OFF \
  -DBUILD_COMPILER=OFF \
  -DBUILD_C_GLIB=OFF \
  -DBUILD_JAVA=OFF \
  -DBUILD_JAVASCRIPT=OFF \
  -DBUILD_NODEJS=OFF \
  -DBUILD_KOTLIN=OFF \
  -DBUILD_PYTHON=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DOPENSSL_ROOT_DIR=${OSQUERY_BUILD}/installed_formulas/openssl
```

## Windows

### Windows x86-64

```cmd
cmake ^
  -S . ^
  -B b ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DBoost_USE_STATIC_LIBS=ON ^
  -DWITH_OPENSSL=ON ^
  -DWITH_ZLIB=ON ^
  -DWITH_LIBEVENT=OFF ^
  -DBUILD_COMPILER=OFF ^
  -DBUILD_C_GLIB=OFF ^
  -DBUILD_JAVA=OFF ^
  -DBUILD_JAVASCRIPT=OFF ^
  -DBUILD_NODEJS=OFF ^
  -DBUILD_KOTLIN=OFF ^
  -DBUILD_PYTHON=OFF ^
  -DCMAKE_BUILD_TYPE=Release ^
  -G "Visual Studio 16 2019" ^
  -A x64
```

### Windows ARM64

```cmd
cmake ^
  -S . ^
  -B b ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DBoost_USE_STATIC_LIBS=ON ^
  -DWITH_OPENSSL=ON ^
  -DWITH_ZLIB=ON ^
  -DWITH_LIBEVENT=OFF ^
  -DBUILD_COMPILER=OFF ^
  -DBUILD_C_GLIB=OFF ^
  -DBUILD_JAVA=OFF ^
  -DBUILD_JAVASCRIPT=OFF ^
  -DBUILD_NODEJS=OFF ^
  -DBUILD_KOTLIN=OFF ^
  -DBUILD_PYTHON=OFF ^
  -DCMAKE_BUILD_TYPE=Release ^
  -G "Visual Studio 16 2019" ^
  -A ARM64
```
