//! Compact XML property lists, byte-identical to `howett.net/plist`'s
//! `plist.XMLFormat` output that upstream sends (no indentation, sorted keys).

const PROLOGUE: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    "<plist version=\"1.0\">"
);
const EPILOGUE: &str = "</plist>";

/// A plist value this writer can emit.
pub(super) enum XmlValue<'a> {
    /// `<string>`.
    String(&'a str),
    /// `<dict>` of the given entries (sorted on output).
    Dict(Vec<(&'a str, XmlValue<'a>)>),
}

/// A complete XML plist document whose root is `root`.
pub(super) fn document(root: &XmlValue<'_>) -> Vec<u8> {
    let mut output = String::from(PROLOGUE);
    write_value(&mut output, root);
    output.push_str(EPILOGUE);
    output.into_bytes()
}

fn write_value(output: &mut String, value: &XmlValue<'_>) {
    match value {
        XmlValue::String(text) => {
            output.push_str("<string>");
            escape_into(output, text);
            output.push_str("</string>");
        }
        XmlValue::Dict(entries) => {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by_key(|(key, _)| *key);
            output.push_str("<dict>");
            for (key, value) in sorted {
                output.push_str("<key>");
                escape_into(output, key);
                output.push_str("</key>");
                write_value(output, value);
            }
            output.push_str("</dict>");
        }
    }
}

/// Go `encoding/xml.EscapeText`.
fn escape_into(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '"' => output.push_str("&#34;"),
            '\'' => output.push_str("&#39;"),
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            other => output.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_and_escapes_like_go() {
        let root = XmlValue::Dict(vec![
            ("b", XmlValue::String("<&>\"'")),
            ("a", XmlValue::Dict(Vec::new())),
        ]);
        let text = String::from_utf8(document(&root)).unwrap();
        assert!(text.ends_with(
            "<plist version=\"1.0\"><dict><key>a</key><dict></dict><key>b</key>\
             <string>&lt;&amp;&gt;&#34;&#39;</string></dict></plist>"
        ));
        assert!(plist::from_bytes::<plist::Value>(text.as_bytes()).is_ok());
    }
}
