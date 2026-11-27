# frozen_string_literal: true

require "test_helper"
require "ferrum"
require "tmpdir"

# Opens built pages in headless Chrome, so decryptor.js runs against real
# WebCrypto and a real DOM. Pages load from file://, which browsers treat as a
# secure context. Without Chrome these tests skip, except on CI.
class TestDecryptor < Minitest::Test
  def self.browser
    return @browser if defined?(@browser)

    @browser = Ferrum::Browser.new(timeout: 10).tap { |browser| Minitest.after_run { browser.quit } }
  rescue Ferrum::BinaryNotFoundError
    raise if ENV["CI"]

    @browser = nil
  end

  def setup
    browser = self.class.browser or skip "Chrome not found"

    @dir = Dir.mktmpdir
    @context = browser.contexts.create
    @page = @context.create_page
  end

  def teardown
    @context&.dispose
    FileUtils.remove_entry(@dir) if @dir
  end

  def open_page(data, filename, **)
    path = File.join(@dir, "page.html")
    File.write(path, StaticEncrypt::Page.build(data, "hunter2", filename: filename, iterations: FAST_ITERATIONS, **))
    @page.go_to("file://#{path}")
  end

  def submit(password)
    input = element("password")
    input.evaluate("this.value = ''")
    input.focus.type(password)
    element("submit").click
  end

  def element(name) = @page.at_css(%([data-static-encrypt="#{name}"]))

  # Reads the page with JavaScript instead of through nodes, which go stale
  # while document.write replaces the page.
  def page_value(expression) = @page.evaluate(expression)

  def decrypted_heading
    wait_until { page_value("document.readyState") == "complete" && @page.title == "Secret" }
    page_value(%(document.querySelector("h1").textContent))
  end

  def wait_until(timeout: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until (result = yield)
      flunk "timed out waiting for the page" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
    result
  end

  def test_html_replaces_the_page
    open_page("<!doctype html><title>Secret</title><h1>héllo wörld</h1>", "index.html")
    submit("hunter2")

    assert_equal "héllo wörld", decrypted_heading
  end

  # Browsers without Uint8Array.fromBase64 decode with atob instead.
  def test_decrypts_without_uint8array_from_base64
    @page.evaluate_on_new_document("delete Uint8Array.fromBase64")
    open_page("<!doctype html><title>Secret</title><h1>héllo wörld</h1>", "index.html")
    submit("hunter2")

    assert_equal "héllo wörld", decrypted_heading
  end

  def test_wrong_password_shows_an_error_and_allows_retry
    open_page("<title>Secret</title>", "index.html")
    submit("wrong")

    wait_until { element("error").text == "Wrong password." }
    refute element("submit").property("disabled")
    assert_nil element("form").attribute("aria-busy")

    submit("hunter2")
    wait_until { @page.title == "Secret" }
  end

  def test_other_files_are_downloaded_with_their_bytes_intact
    bytes = (0..255).map(&:chr).join.b
    downloads = File.join(@dir, "downloads")
    open_page(bytes, "data.bin")
    @page.downloads.set_behavior(save_path: downloads)

    @page.downloads.await_download! { submit("hunter2") }

    assert_equal "Download data.bin", @page.at_css("a").text
    assert_equal bytes, File.binread(File.join(downloads, "data.bin"))
  end

  def test_messages_can_be_overridden_on_the_form
    template = StaticEncrypt::Page.default_template
                                  .sub('<form data-static-encrypt="form"', '<form data-static-encrypt="form" data-wrong-password-message="Nope."')
    open_page("<title>Secret</title>", "index.html", template: template)
    submit("wrong")

    wait_until { element("error").text == "Nope." }
  end
end
