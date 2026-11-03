# frozen_string_literal: true

require_relative "static_encrypt/version"
require_relative "static_encrypt/cipher"
require_relative "static_encrypt/page"

module StaticEncrypt
  class Error < StandardError; end
  class DecryptionError < Error; end
end
