VARIABLES=

WIN_CC=/usr/bin/x86_64-w64-mingw32-gcc

WIN_FLAGS=-Wl,--out-implib,libshad0w_modules_dll.a

base64.o:
        $(WIN_CC) -c -DBUILDING_EXAMPLE_DLL base64.c
crypt.o:
        $(WIN_CC) -c -DBUILDING_EXAMPLE_DLL crypt.c

dll:
        $(WIN_CC) -shared -o libshad0w_modules.dll base64.o crypt.o $(WIN_FLAGS)

all: base64.o crypt.o dll

clean:
        rm base64.o crypt.o libshad0w_modules_dll.a libshad0w_modules.dll
