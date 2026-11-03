# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "static_encrypt"

require "minitest/autorun"

# Keeps the suite fast; real pages use Cipher::DEFAULT_ITERATIONS.
FAST_ITERATIONS = 1_000
