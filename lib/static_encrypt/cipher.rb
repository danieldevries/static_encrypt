# frozen_string_literal: true

require "openssl"
require "securerandom"

module StaticEncrypt
  # AES-256-GCM encryption with a PBKDF2-HMAC-SHA256 derived key, laid out the
  # way WebCrypto expects it so the browser can decrypt the result.
  module Cipher
    DEFAULT_ITERATIONS = 600_000
    SALT_BYTES = 16
    IV_BYTES = 12
    TAG_BYTES = 16

    module_function

    def encrypt(data, password, iterations: DEFAULT_ITERATIONS)
      raise ArgumentError, "password must not be empty" if password.to_s.empty?
      raise ArgumentError, "iterations must be a positive integer" unless valid_iterations?(iterations)

      salt = SecureRandom.random_bytes(SALT_BYTES)
      iv = SecureRandom.random_bytes(IV_BYTES)

      cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
      cipher.key = derive_key(password, salt, iterations)
      cipher.iv = iv
      cipher.auth_data = ""
      ciphertext = cipher.update(data) + cipher.final + cipher.auth_tag

      { salt: encode64(salt), iv: encode64(iv), data: encode64(ciphertext), iterations: iterations }
    end

    def decrypt(payload, password)
      salt, iv, raw, iterations = parse(payload)
      ciphertext = raw.byteslice(0...-TAG_BYTES)
      tag = raw.byteslice(-TAG_BYTES..)

      cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      cipher.key = derive_key(password, salt, iterations)
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = ""
      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      raise DecryptionError, "wrong password or corrupted data"
    end

    def parse(payload)
      payload = payload.to_h.transform_keys(&:to_sym)
      salt, iv, raw = payload.fetch_values(:salt, :iv, :data).map { decode64(_1) }
      iterations = payload.fetch(:iterations)

      raise DecryptionError, "malformed payload: bad iterations" unless valid_iterations?(iterations)
      raise DecryptionError, "malformed payload: bad salt" if salt.empty?
      raise DecryptionError, "malformed payload: IV must be #{IV_BYTES} bytes" unless iv.bytesize == IV_BYTES
      raise DecryptionError, "malformed payload: data too short" if raw.bytesize < TAG_BYTES

      [salt, iv, raw, iterations]
    rescue KeyError, ArgumentError, TypeError, NoMethodError => e
      raise DecryptionError, "malformed payload: #{e.message}"
    end

    def valid_iterations?(iterations) = iterations.is_a?(Integer) && iterations.positive?

    def derive_key(password, salt, iterations)
      OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iterations, length: 32, hash: "sha256")
    end

    def encode64(bytes) = [bytes].pack("m0")
    def decode64(string) = string.unpack1("m0")
  end
end
