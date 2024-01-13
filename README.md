# Build & Test

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
