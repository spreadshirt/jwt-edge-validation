SHELL := /bin/bash

.PHONY: build release

SOURCES:=$(wildcard src/*.rs)

all: build

clean:
	@cargo clean
	@rm -rf target

build: module.wasm

module.wasm: target/wasm32-unknown-unknown/release/jwt_edge_validation.wasm
	@cp $< $@

target/wasm32-unknown-unknown/release/jwt_edge_validation.wasm: $(SOURCES)
	@cargo +nightly build --release --target wasm32-unknown-unknown

test: module.wasm
	@cargo +nightly test

deploy: module.wasm
	@terrctl -language=wasm $<
