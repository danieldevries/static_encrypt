# frozen_string_literal: true

require "test_helper"

class TestPage < Minitest::Test
  def build(data, filename, **options)
    StaticEncrypt::Page.build(data, "hunter2", filename: filename, iterations: FAST_ITERATIONS, **options)
  end

  def test_embedded_payload_decrypts
    html = build("<h1>Hi</h1>", "index.html")
    payload = StaticEncrypt::Page.payload(html)

    assert_equal "<h1>Hi</h1>", StaticEncrypt::Cipher.decrypt(payload, "hunter2")
    assert payload[:html]
    assert_equal "text/html", payload[:mime]
  end

  def test_non_html_file_is_offered_as_download
    payload = StaticEncrypt::Page.payload(build("%PDF", "report.pdf"))

    refute payload[:html]
    assert_equal "report.pdf", payload[:name]
    assert_equal "application/pdf", payload[:mime]
  end

  def test_unknown_extension_falls_back_to_octet_stream
    assert_equal "application/octet-stream", StaticEncrypt::Page.payload(build("x", "data.bin"))[:mime]
  end

  def test_title_and_instructions_are_escaped
    html = build("x", "a.txt", title: "</title><script>", instructions: "a & b")

    assert_includes html, "<title>&lt;/title&gt;&lt;script&gt;</title>"
    assert_includes html, "<p>a &amp; b</p>"
  end

  def test_title_fills_every_placeholder
    html = build("x", "a.txt", title: "My Title")

    assert_includes html, "<title>My Title</title>"
    assert_includes html, "<h1>My Title</h1>"
    refute_match(/\{\{\w+\}\}/, html)
  end

  def test_placeholders_in_values_are_not_expanded
    html = build("secret", "a.txt", title: "{{payload}}", instructions: "{{title}}")

    assert_includes html, "<h1>{{payload}}</h1>"
    assert_includes html, "<p>{{title}}</p>"
    assert_equal "secret", StaticEncrypt::Cipher.decrypt(StaticEncrypt::Page.payload(html), "hunter2")
  end

  def test_filename_cannot_break_out_of_script
    ["</script>.txt", "<!--<script>.txt", "<script>.txt"].each do |name|
      html = build("x", name)
      payload_line = html[/^\s*const payload = .*$/]

      refute_includes payload_line, "<", "raw '<' in payload for #{name}"
      assert_equal 1, html.scan("</script>").size, "only the template's own </script> for #{name}"
      assert_equal name, StaticEncrypt::Page.payload(html)[:name]
    end
  end

  MINIMAL_TEMPLATE = <<~HTML
    <title>{{title}}</title>
    <form data-static-encrypt=form><input data-static-encrypt='password'><div data-static-encrypt="error"></div></form>
    {{script}}
  HTML

  def test_custom_template
    html = build("secret", "a.txt", template: MINIMAL_TEMPLATE, title: "Mine")

    assert html.start_with?("<title>Mine</title>\n<form data-static-encrypt=form>")
    assert_equal "secret", StaticEncrypt::Cipher.decrypt(StaticEncrypt::Page.payload(html), "hunter2")
    assert_includes html, StaticEncrypt::Page.decryptor
  end

  def test_default_template_is_valid
    assert StaticEncrypt::Page.validate_template!(StaticEncrypt::Page.default_template)
  end

  def test_template_without_script_placeholder_is_rejected
    error = assert_raises(StaticEncrypt::Error) { build("x", "a.txt", template: MINIMAL_TEMPLATE.sub("{{script}}", "")) }
    assert_match "{{script}} exactly once", error.message
  end

  def test_template_with_two_script_placeholders_is_rejected
    assert_raises(StaticEncrypt::Error) { build("x", "a.txt", template: "#{MINIMAL_TEMPLATE}{{script}}") }
  end

  def test_template_with_unknown_placeholder_is_rejected
    error = assert_raises(StaticEncrypt::Error) { build("x", "a.txt", template: "#{MINIMAL_TEMPLATE}{{footer}}") }
    assert_match "{{footer}}", error.message
  end

  def test_template_missing_elements_is_rejected
    template = MINIMAL_TEMPLATE.sub("data-static-encrypt='password'", "")
                               .sub('data-static-encrypt="error"', 'data-static-encrypt="errors"')
    error = assert_raises(StaticEncrypt::Error) { build("x", "a.txt", template: template) }

    assert_match 'data-static-encrypt="password"', error.message
    assert_match 'data-static-encrypt="error"', error.message
  end

  def test_plaintext_not_in_page
    refute_includes build("top secret contents", "a.txt"), "top secret"
  end
end
