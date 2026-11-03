# frozen_string_literal: true

require "cgi/escape"
require "json"

module StaticEncrypt
  module Page
    TEMPLATE_PATH = File.expand_path("template.html", __dir__)
    DECRYPTOR_PATH = File.expand_path("decryptor.js", __dir__)

    DEFAULT_TITLE = "Protected Page"
    DEFAULT_INSTRUCTIONS = "Enter the password to view this content."

    PLACEHOLDER = /\{\{(\w+)\}\}/
    PLACEHOLDERS = %w[title instructions script].freeze
    REQUIRED_ELEMENTS = %w[form password error].freeze

    MIME_TYPES = {
      ".html" => "text/html", ".htm" => "text/html", ".txt" => "text/plain",
      ".md" => "text/markdown", ".csv" => "text/csv", ".json" => "application/json",
      ".pdf" => "application/pdf", ".zip" => "application/zip",
      ".png" => "image/png", ".jpg" => "image/jpeg", ".jpeg" => "image/jpeg",
      ".gif" => "image/gif", ".svg" => "image/svg+xml", ".webp" => "image/webp",
      ".mp3" => "audio/mpeg", ".mp4" => "video/mp4"
    }.freeze

    module_function

    def build(data, password, filename:, template: default_template, title: DEFAULT_TITLE,
              instructions: DEFAULT_INSTRUCTIONS, iterations: Cipher::DEFAULT_ITERATIONS)
      validate_template!(template)

      ext = File.extname(filename).downcase
      payload = Cipher.encrypt(data, password, iterations: iterations).merge(
        name: filename,
        mime: MIME_TYPES.fetch(ext, "application/octet-stream"),
        html: %w[.html .htm].include?(ext)
      )

      values = {
        "title" => CGI.escapeHTML(title),
        "instructions" => CGI.escapeHTML(instructions),
        "script" => script(payload)
      }
      template.gsub(PLACEHOLDER) { values.fetch(Regexp.last_match(1)) }
    end

    def script(payload)
      json = JSON.generate(payload).gsub("<", "\\u003c")
      "<script>\n(() => {\n\"use strict\";\nconst payload = #{json};\n#{decryptor}})();\n</script>"
    end

    def validate_template!(template)
      names = template.scan(PLACEHOLDER).flatten
      unknown = names.uniq - PLACEHOLDERS

      raise Error, "unknown template placeholder(s): #{unknown.map { "{{#{_1}}}" }.join(", ")}" if unknown.any?
      raise Error, "template must contain {{script}} exactly once" unless names.count("script") == 1

      missing = REQUIRED_ELEMENTS.reject { template.match?(/data-static-encrypt\s*=\s*["']?#{_1}["'\s>]/) }

      raise Error, "template is missing #{missing.map { %(data-static-encrypt="#{_1}") }.join(", ")}" if missing.any?

      template
    end

    def payload(html)
      json = html[/const payload = (\{.*?\});$/, 1] or raise Error, "no encrypted payload found"
      JSON.parse(json, symbolize_names: true)
    end

    def default_template
      @default_template ||= File.read(TEMPLATE_PATH, encoding: "UTF-8")
    end

    def decryptor
      @decryptor ||= File.read(DECRYPTOR_PATH, encoding: "UTF-8")
    end
  end
end
