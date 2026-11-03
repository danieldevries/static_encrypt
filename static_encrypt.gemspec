# frozen_string_literal: true

require_relative "lib/static_encrypt/version"

Gem::Specification.new do |spec|
  spec.name = "static_encrypt"
  spec.version = StaticEncrypt::VERSION
  spec.authors = ["Daniël de Vries"]
  spec.email = ["contact@danieldevries.eu"]

  spec.summary = "Password-protect files as self-contained static HTML pages."
  spec.description = <<~DESC
    Encrypts a file with AES-256-GCM (PBKDF2-SHA256 key derivation) and wraps it in a
    single HTML page that decrypts in the browser with WebCrypto. Host it anywhere.
  DESC
  spec.homepage = "https://github.com/danieldevries/static_encrypt"
  spec.required_ruby_version = ">= 3.2.0"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*", "README.md", "LICENSE.txt"]
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
