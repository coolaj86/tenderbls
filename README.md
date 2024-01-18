# Tenderbls

This copies the BLS parts from Tenderdash to be able to run standalone, and compare against Pure Go implementations of Chia / Relic BLS.

- Go (Kilic)
- TinyGo
- WASM
- CGO (Relic)

# Build & Test Go / TinyGo

```sh
curl https://webi.sh/go | sh
source ~/.config/envman/PATH.env

go build ./cmd/chiabls
```

```sh
curl https://webi.sh/tinygo | sh
source ~/.config/envman/PATH.env

tinygo build --tags generic ./cmd/chiabls
```

## WASM

```sh
curl https://webi.sh/rust | sh
curl https://webi.sh/tinygo | sh
source ~/.config/envman/PATH.env

cargo install wasm-opt

tinygo build --tags generic \
    -o chiabls.wasm -target=wasi \
    ./cmd/chiabls
```

```sh
GOOS=wasip1 GOARCH=wasm go build -o chiabls.wasm ./cmd/chiabls
```

# Build & Test CGO

```sh
git submodule init
git submodule update

make build-bls

sudo cp \
    ./third_party/bls-signatures/build/depends/mimalloc/libmimalloc-secure.a \
    ./third_party/bls-signatures/build/depends/relic/lib/librelic_s.a \
    ./third_party/bls-signatures/build/src/libdashbls.a \
    /usr/local/lib/

sudo cp -R \
    ./third_party/bls-signatures/src/include/dashbls \
    /usr/local/include/

sudo cp -R \
    ./third_party/bls-signatures/src/depends/relic/include \
    /usr/local/include/relic

sudo cp -R \
    ./third_party/bls-signatures/build/depends/relic/include/relic_conf.h \
    ./third_party/bls-signatures/src/depends/relic/include/*.h \
    /usr/local/include/dashbls/

go test -count 1 ./crypto/bls12381/
```

# TODO

```text
~/.local/opt/relic/lib/
~/.local/opt/relic/include/
~/.local/opt/dashbls/lib/
~/.local/opt/dashbls/include/
~/.local/opt/mimalloc/lib/
```
