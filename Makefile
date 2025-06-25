check:
	cargo check --quiet --no-default-features 
	cargo check --quiet --all-features
	cargo check --quiet --no-default-features --target wasm32-unknown-unknown
	cargo check --quiet --all-features --target wasm32-unknown-unknown

test:
	cargo test --all-features

doc:
	cargo doc
	cp ./build/vendored-docs-redirect.index.html target/doc/index.html

bench:
	cargo bench

# Lints with everything we have in our CI arsenal
lint-all: lint-fmt clippy license spellcheck deny

deny:
	cargo deny check bans licenses sources || (echo "See deny.toml"; false)

deny-advisories:
	cargo deny check advisories || (echo "See deny.toml"; false)

lint-fmt:
	cargo fmt --all --check
	taplo fmt --check
	taplo lint
	corepack enable && yarn && yarn md-check

fmt:
	cargo fmt --all
	taplo fmt
	corepack enable && yarn && yarn md-fmt

clippy:
	cargo clippy --all-targets --all-features --quiet --no-deps -- --deny=warnings
	cargo clippy --all-features --target wasm32-unknown-unknown --quiet --no-deps -- --deny=warnings

# Checks if all headers are present and adds if not
license:
	./scripts/add_license.sh

spellcheck:
	cargo spellcheck --code 1 || (echo "See .config/spellcheck.md for tips"; false)

install-lint-tools:
	cargo install --locked taplo-cli
	cargo install --locked cargo-deny
	cargo install --locked cargo-spellcheck

install-lint-tools-ci:
	wget https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz
	tar xzf cargo-binstall-x86_64-unknown-linux-musl.tgz
	cp cargo-binstall ~/.cargo/bin/cargo-binstall

	cargo binstall --no-confirm taplo-cli cargo-spellcheck cargo-deny
