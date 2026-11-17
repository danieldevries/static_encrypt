# frozen_string_literal: true

require_relative "static_encrypt/version"
require_relative "static_encrypt/cipher"
require_relative "static_encrypt/page"

# Password-protect files as self-contained static HTML pages.
#
# The file is encrypted with AES-256-GCM using a key derived from the password
# with PBKDF2-HMAC-SHA256. The resulting page contains only the ciphertext plus
# a small WebCrypto-based decryptor, so it can be hosted anywhere. HTML files
# are rendered in place once decrypted; any other file is offered as a download.
#
#   html = StaticEncrypt.encrypt_file("page.html", "hunter2", title: "My Page")
#   File.write("protected.html", html)
module StaticEncrypt
  class Error < StandardError; end
  class DecryptionError < Error; end

  module_function

  def encrypt_file(path, password, **)
    Page.build(File.binread(path), password, filename: File.basename(path), **)
  end
end
