# StaticEncrypt

Password-protect any file as a single, self-contained HTML page. A Ruby take on
[StatiCrypt](https://github.com/robinmoisson/staticrypt).

The file is encrypted with AES-256-GCM, using a key derived from your password
with PBKDF2-HMAC-SHA256 (600,000 iterations). The page holds only the
ciphertext and a small decryptor that runs in the browser with WebCrypto, so you
can host it anywhere static: GitHub Pages, S3, Netlify.

## Installation

```sh
gem install static_encrypt
```

Or, from a checkout:

```sh
bundle install
bundle exec rake install
```

## Usage

Currently, the only way to use this gem is via Ruby: pass the file's contents,
a password and the file's name to `Page.build`. It returns the
password-protected page as a string:

```ruby
require "static_encrypt"

html = StaticEncrypt::Page.build(File.binread("home.html"), "secret", filename: "home.html")
File.write("home.encrypted.html", html)
```

Open the page, enter the password, and an HTML file replaces the page; any
other file (a PDF, an image) is offered as a download under its original name.
The `filename` is what decides which, its extension sets the download's type.

Optional keyword arguments:

| Argument | Default |
|---|---|
| `title:` | `"Protected Page"` |
| `instructions:` | `"Enter the password to view this content."` |
| `iterations:` | `600_000` PBKDF2 iterations |
| `template:` | The built-in page; see below |

To check a page from Ruby, read its payload back and decrypt it. A wrong
password raises `StaticEncrypt::DecryptionError`:

```ruby
payload = StaticEncrypt::Page.payload(html)
StaticEncrypt::Cipher.decrypt(payload, "secret") # => the original bytes
```

### Custom templates

`template:` takes your own HTML as a string. Start from
`StaticEncrypt::Page.default_template`, or write one that has:

- `{{script}}` exactly once, where the decryptor is inserted
- elements with `data-static-encrypt="form"`, `"password"` and `"error"`
  (and optionally `"submit"`)
- optionally `{{title}}` and `{{instructions}}`

`Page.build` raises `StaticEncrypt::Error` if any of that is missing.

### Hosting

Browsers only decrypt over **HTTPS** (or on `localhost`, or from a local file).
Anyone can download the page and guess passwords offline, so use a long,
random one.

