@echo on
CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
mkdir build
cd build
REM SPHINCS and Rainbow cause a big slowdown in the tests
cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_ENABLE_SIG_SPHINCS=OFF -DOQS_ENABLE_SIG_RAINBOW=OFF -DBUILD_SHARED_LIBS=%BUILD_SHARED%
ninja

