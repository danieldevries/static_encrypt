# frozen_string_literal: true

require "test_helper"

class TestCipher < Minitest::Test
  def encrypt(data, password = "hunter2")
    StaticEncrypt::Cipher.encrypt(data, password, iterations: FAST_ITERATIONS)
  end

  def test_round_trip
    payload = encrypt("héllo wörld".b)

    assert_equal "héllo wörld".b, StaticEncrypt::Cipher.decrypt(payload, "hunter2")
  end

  def test_round_trip_binary
    data = Random.bytes(10_000)

    assert_equal data, StaticEncrypt::Cipher.decrypt(encrypt(data), "hunter2")
  end

  def test_wrong_password_raises
    assert_raises(StaticEncrypt::DecryptionError) do
      StaticEncrypt::Cipher.decrypt(encrypt("secret"), "wrong")
    end
  end

  def test_tampered_data_raises
    payload = encrypt("secret")
    raw = payload[:data].unpack1("m0")
    raw.setbyte(0, raw.getbyte(0) ^ 1)

    assert_raises(StaticEncrypt::DecryptionError) do
      StaticEncrypt::Cipher.decrypt(payload.merge(data: [raw].pack("m0")), "hunter2")
    end
  end

  def test_salt_and_iv_are_random
    a = encrypt("same")
    b = encrypt("same")

    refute_equal a[:salt], b[:salt]
    refute_equal a[:iv], b[:iv]
    refute_equal a[:data], b[:data]
  end

  def test_empty_password_rejected
    assert_raises(ArgumentError) do
      encrypt("data", "")
    end
  end

  def test_non_positive_iterations_rejected
    [0, -1, 1.5, "1000"].each do |iterations|
      assert_raises(ArgumentError) do
        StaticEncrypt::Cipher.encrypt("data", "pw", iterations: iterations)
      end
    end
  end

  def test_malformed_payloads_raise_decryption_error
    valid = encrypt("secret")
    malformed = {
      "missing key" => valid.except(:salt),
      "invalid base64" => valid.merge(iv: "not base64!"),
      "short data" => valid.merge(data: "AA=="),
      "wrong IV length" => valid.merge(iv: "AA=="),
      "zero iterations" => valid.merge(iterations: 0),
      "string iterations" => valid.merge(iterations: "1000"),
      "nil field" => valid.merge(data: nil),
      "not a hash" => []
    }

    malformed.each do |label, payload|
      error = assert_raises(StaticEncrypt::DecryptionError, label) do
        StaticEncrypt::Cipher.decrypt(payload, "hunter2")
      end
      assert_match "malformed payload", error.message, label
    end
  end

  def test_accepts_string_keys
    payload = encrypt("secret").transform_keys(&:to_s)

    assert_equal "secret", StaticEncrypt::Cipher.decrypt(payload, "hunter2")
  end
end
