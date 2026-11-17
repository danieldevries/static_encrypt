# frozen_string_literal: true

require "optparse"
require "io/console"
require_relative "../static_encrypt"

module StaticEncrypt
  # The static-encrypt command: encrypts a file into a password-protected HTML page.
  # Run it with --help to see the options.
  class CLI
    PASSWORD_ENV = "STATIC_ENCRYPT_PASSWORD"

    def self.start(argv = ARGV) = exit(new.run(argv))

    def initialize(env: ENV, stdin: $stdin, stdout: $stdout, stderr: $stderr)
      @env = env
      @stdin = stdin
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      options = parse(argv.dup)
      return 0 if options[:exit]

      input = options.delete(:input)
      raise Error, "no such file: #{input}" unless File.file?(input)

      # Read and check the template before asking for a password.
      options[:template] = Page.validate_template!(File.read(options[:template])) if options[:template]

      output = options.delete(:output) || default_output(input)
      File.write(output, StaticEncrypt.encrypt_file(input, password(options.delete(:password)), **options))
      @stdout.puts "Encrypted #{input} -> #{output}"
      0
    rescue Error, OptionParser::ParseError, SystemCallError => e
      @stderr.puts "static-encrypt: #{e.message}"
      1
    end

    private

    def parse(argv)
      options = {}
      parser = option_parser
      parser.parse!(argv, into: options)

      return { exit: true } if options.keys.intersect?(%i[print-template version help])

      options[:input] = argv.shift or raise Error, "missing FILE\n#{parser}"
      options
    end

    def option_parser
      OptionParser.new do |o|
        o.banner = "Usage: static-encrypt FILE [options]"
        o.version = VERSION
        o.on("-p", "--password PASSWORD", "Password (else $#{PASSWORD_ENV}, else prompt)")
        o.on("-o", "--output PATH", "Output file (default: home.html -> home.encrypted.html)")
        o.on("-t", "--title TITLE", "Title shown on the password page")
        o.on("-i", "--instructions TEXT", "Text shown under the title")
        o.on("--template PATH", "Custom HTML template (start from --print-template)")
        o.on("--print-template", "Print the default template and exit") do
          @stdout.print Page.default_template
        end
        o.on("--iterations N", Integer, "PBKDF2 iterations (default: #{Cipher::DEFAULT_ITERATIONS})") do |n|
          n.positive? ? n : raise(Error, "--iterations must be at least 1")
        end
        o.on("-v", "--version", "Print the version") { @stdout.puts VERSION }
        o.on("-h", "--help", "Show this help") { @stdout.puts o }
      end
    end

    def default_output(input)
      ext = File.extname(input)
      base = %w[.html .htm].include?(ext.downcase) ? input.delete_suffix(ext) : input
      "#{base}.encrypted.html"
    end

    def password(given)
      password = given || @env[PASSWORD_ENV] || prompt_password
      raise Error, "password must not be empty" if password.empty?

      password
    end

    def prompt_password
      raise Error, "no password given and stdin is not a terminal" unless @stdin.tty?

      password = @stdin.getpass("Password: ")
      confirmation = @stdin.getpass("Confirmation: ")

      raise Error, "passwords do not match" unless confirmation == password

      password
    end
  end
end
