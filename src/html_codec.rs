use encoding_rs::{Encoding, UTF_8};

pub struct DecodedHtml {
    text: String,
    encoding: &'static Encoding,
}

impl DecodedHtml {
    pub fn decode(body: &[u8], content_type: Option<&str>) -> Self {
        let encoding = detect_html_encoding(body, content_type);
        let (text, _, _) = encoding.decode(body);
        Self {
            text: text.into_owned(),
            encoding,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn encode(&self, text: &str) -> Vec<u8> {
        let (bytes, _, _) = self.encoding.encode(text);
        bytes.into_owned()
    }
}

fn detect_html_encoding(body: &[u8], content_type: Option<&str>) -> &'static Encoding {
    detect_encoding_from_content_type(content_type)
        .or_else(|| detect_encoding_from_meta(body))
        .unwrap_or(UTF_8)
}

fn detect_encoding_from_content_type(content_type: Option<&str>) -> Option<&'static Encoding> {
    let content_type = content_type?;

    for part in content_type.split(';').skip(1) {
        if let Some((name, value)) = part.split_once('=') {
            if !name.trim().eq_ignore_ascii_case("charset") {
                continue;
            }
            let label = value.trim().trim_matches('"').trim_matches('\'');
            if let Some(encoding) = Encoding::for_label(label.as_bytes()) {
                return Some(encoding);
            }
        }
    }

    None
}

fn detect_encoding_from_meta(body: &[u8]) -> Option<&'static Encoding> {
    let prefix_len = body.len().min(4096);
    let prefix = String::from_utf8_lossy(&body[..prefix_len]).to_ascii_lowercase();

    if let Some(label) = capture_charset_value(&prefix, "charset=") {
        if let Some(encoding) = Encoding::for_label(label.as_bytes()) {
            return Some(encoding);
        }
    }

    if let Some(meta_index) = prefix.find("content-type") {
        let meta_tail = &prefix[meta_index..];
        if let Some(label) = capture_charset_value(meta_tail, "charset=") {
            if let Some(encoding) = Encoding::for_label(label.as_bytes()) {
                return Some(encoding);
            }
        }
    }

    None
}

fn capture_charset_value(text: &str, marker: &str) -> Option<String> {
    let start = text.find(marker)? + marker.len();
    let tail = text[start..]
        .trim_start()
        .trim_start_matches(['"', '\''])
        .trim_start();
    let end = tail
        .find(|ch: char| ch == '"' || ch == '\'' || ch == ';' || ch == '>' || ch.is_whitespace())
        .unwrap_or(tail.len());
    let value = tail[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::DecodedHtml;

    #[test]
    fn decodes_quoted_meta_charset() {
        let html = b"<html><head><meta charset=\"shift_jis\"></head><body>\x93\xfa\x96\x7b\x8c\xea</body></html>";

        let decoded = DecodedHtml::decode(html, None);

        assert_eq!(decoded.encode(decoded.text()), html);
    }

    #[test]
    fn decodes_quoted_content_type_charset() {
        let html = b"<html><body>\x93\xfa\x96\x7b\x8c\xea</body></html>";

        let decoded = DecodedHtml::decode(html, Some("text/html; foo; charset=\"shift_jis\""));

        assert_eq!(decoded.encode(decoded.text()), html);
    }
}
