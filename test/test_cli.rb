# frozen_string_literal: true

require "test_helper"
require "stringio"
require "tmpdir"

class TestCLI < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @input = File.join(@dir, "page.html")
    File.write(@input, "<p>hello</p>")
    @stdout = StringIO.new
    @stderr = StringIO.new
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def run_cli(*argv, env: {})
    StaticEncrypt::CLI.new(env: env, stdin: StringIO.new, stdout: @stdout, stderr: @stderr)
                      .run([*argv, "--iterations", FAST_ITERATIONS.to_s])
  end

  def decrypt(path, password)
    StaticEncrypt::Cipher.decrypt(StaticEncrypt::Page.payload(File.read(path)), password)
  end

  def test_encrypts_with_password_flag
    assert_equal 0, run_cli(@input, "-p", "hunter2")
    assert_equal "<p>hello</p>", decrypt(File.join(@dir, "page.encrypted.html"), "hunter2")
    assert_match "Encrypted", @stdout.string
  end

  def test_default_output_names
    {
      "home.html" => "home.encrypted.html",
      "old.HTM" => "old.encrypted.html",
      "report.pdf" => "report.pdf.encrypted.html",
      "notes" => "notes.encrypted.html",
      "site.v2.html" => "site.v2.encrypted.html"
    }.each do |name, expected|
      input = File.join(@dir, name)
      File.write(input, "x")

      assert_equal 0, run_cli(input, "-p", "x"), name
      assert File.file?(File.join(@dir, expected)), "#{name} should produce #{expected}"
    end
  end

  def test_reads_password_from_env_and_honours_output
    output = File.join(@dir, "out.html")

    assert_equal 0, run_cli(@input, "-o", output, env: { "STATIC_ENCRYPT_PASSWORD" => "from-env" })
    assert_equal "<p>hello</p>", decrypt(output, "from-env")
  end

  def test_fails_without_password_on_non_tty
    assert_equal 1, run_cli(@input)
    assert_match "stdin is not a terminal", @stderr.string
  end

  def test_fails_on_missing_file
    assert_equal 1, run_cli(File.join(@dir, "nope.html"), "-p", "x")
    assert_match "no such file", @stderr.string
  end

  def test_fails_without_file_argument
    assert_equal 1, run_cli("-p", "x")
    assert_match "missing FILE", @stderr.string
  end

  def test_rejects_non_positive_iterations
    status = StaticEncrypt::CLI.new(env: {}, stdout: @stdout, stderr: @stderr)
                               .run([@input, "-p", "x", "--iterations", "0"])

    assert_equal 1, status
    assert_match "--iterations must be at least 1", @stderr.string
  end

  def test_reports_unreadable_input_without_backtrace
    File.chmod(0o000, @input)
    skip "running as root; file stays readable" if File.readable?(@input)

    assert_equal 1, run_cli(@input, "-p", "x")
    assert_match(/static-encrypt: Permission denied/, @stderr.string)
  end

  def test_reports_unwritable_output_without_backtrace
    assert_equal 1, run_cli(@input, "-p", "x", "-o", File.join(@dir, "missing", "out.html"))
    assert_match(/static-encrypt: No such file or directory/, @stderr.string)
  end

  def test_custom_template
    template = File.join(@dir, "template.html")
    File.write(template, StaticEncrypt::Page.default_template.sub("<body>", '<body class="mine">'))

    assert_equal 0, run_cli(@input, "-p", "hunter2", "--template", template)
    output = File.join(@dir, "page.encrypted.html")
    assert_includes File.read(output), '<body class="mine">'
    assert_equal "<p>hello</p>", decrypt(output, "hunter2")
  end

  def test_print_template
    assert_equal 0, StaticEncrypt::CLI.new(stdout: @stdout).run(["--print-template"])
    assert_equal StaticEncrypt::Page.default_template, @stdout.string
  end

  def test_invalid_template_fails_before_asking_for_password
    template = File.join(@dir, "bad.html")
    File.write(template, "<p>no placeholders</p>")

    # No password and a non-TTY stdin: a password prompt would fail differently.
    assert_equal 1, run_cli(@input, "--template", template)
    assert_match "{{script}} exactly once", @stderr.string
  end

  def test_missing_template_file
    assert_equal 1, run_cli(@input, "-p", "x", "--template", File.join(@dir, "nope.html"))
    assert_match "No such file or directory", @stderr.string
  end

  def test_version
    assert_equal 0, StaticEncrypt::CLI.new(stdout: @stdout).run(["--version"])
    assert_equal StaticEncrypt::VERSION, @stdout.string.strip
  end
end
