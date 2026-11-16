# Landing page languages

One file per language: `<code>.json`. `en.json` is the source; every other file is a
translation of it. The pages at `https://mcp.scanmalware.com/<code>/`, the language menu,
the `hreflang` and Open Graph tags, the sitemap and the browser-language redirect in
`nginx.conf` are all generated from these files by `../build.py`.

## Adding a language

You need two files from this directory and nothing else: this README and `en.json`
(`sv.json` is a finished translation to compare with). Both are public:

- https://raw.githubusercontent.com/scanmalware/mcp-server/main/deploy/nginx/landing/locales/en.json
- https://raw.githubusercontent.com/scanmalware/mcp-server/main/deploy/nginx/landing/locales/README.md

1. Copy `en.json` to `<code>.json`. The code is lowercase and becomes the URL: `de`, `fr`,
   `pt-br`, `zh-tw`. Use the same codes as scanmalware.com and status.scanmalware.com.
2. Set the five settings at the top of the file (table below).
3. Translate every other value. Keep every key; add none.
4. Hand the file to whoever maintains the MCP server repo. They drop it into this directory
   and run the build; no other file needs editing.

### Settings

| Key | What it is | `sv` | `pt-br` | `ar` |
|---|---|---|---|---|
| `html_lang` | BCP 47 tag for `<html lang>` and `hreflang` | `sv` | `pt-BR` | `ar` |
| `language_name` | The language's own name, as shown in the menu | `Svenska` | `Português (Brasil)` | `العربية` |
| `dir` | Text direction, `ltr` or `rtl` | `ltr` | `ltr` | `rtl` |
| `og_locale` | Open Graph locale, `ll_CC` | `sv_SE` | `pt_BR` | `ar_SA` |
| `accept_language` | Lowercase browser-language prefixes that send a visitor of `/` to this page | `["sv"]` | `["pt"]` | `["ar"]` |

`accept_language` is matched against the start of the browser's first language, whole
subtags only: `["zh"]` takes `zh`, `zh-CN` and `zh-TW`, `["zh-tw", "zh-hk"]` takes only
those two. The longer prefix wins, so `zh-tw` and `zh` can live in different files. Two
languages cannot claim the same prefix. A regional variant of a language that is already
here should claim its region (`["pt-br"]`), not the whole language.

### Translating

- The values are HTML. Keep every tag exactly as it is in English, attributes included:
  `<a href="…" rel="noopener">`, `<strong>`, `<code>`. Translate the text between the tags;
  move tags within the sentence as the grammar needs. No new tags, none dropped.
- Leave the text inside `<code>…</code>` in English (`public`, `private`, `tools/list`):
  those are literal values a reader types or sees.
- Product and protocol names stay as they are: ScanMalware, Claude, ChatGPT, Gemini CLI,
  MCP, Model Context Protocol, Streamable HTTP, SMQL, JARM, YARA, Triop AB.
- A literal `<`, `>` or `&` in your text is written `&lt;`, `&gt;`, `&amp;`.
- `meta_description` is the search-result and link-preview text: plain text, no tags, and
  about as long as the English one.
- Translate the meaning, not the words. Security terms get the term practitioners use in
  that language; where the English term is what they would search for, keep it in
  brackets, as `sv.json` does with "indikatorer på intrång (IOC)".
- Commands, URLs and tool names are not in these files. They live in `../template.html`
  and are the same in every language.

## Checking and building

With a checkout of the repo (it is public, so a translator can do this too):

```sh
python3 deploy/nginx/landing/build.py --validate path/to/de.json   # checks one file, writes nothing
cp path/to/de.json deploy/nginx/landing/locales/
python3 deploy/nginx/landing/build.py                              # pages, sitemap, nginx map
python3 -m unittest discover -s tests/maintenance -p test_landing_page.py
```

The build refuses a file with a missing or extra key, a tag that differs from English,
changed `<code>` text, or a setting of the wrong shape, and says which key. Commit the
locale file together with everything the build wrote.

Deploying: the `html/` directory is mounted into nginx, so the new page is live as soon as
the files are on the server. The redirect for the new language is in `nginx.conf`, which
needs `nginx -t` and a reload (`docs/OPERATIONS.md`).

## Changing the English text

Change `en.json`, then the same key in every other file. A new key must be added to every
language before the build passes; until a translation arrives, put the English text in the
other files so no page is left with a hole.

The language menu lists English first, then the others by code.
