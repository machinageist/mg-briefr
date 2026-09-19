// Author: Jeff
// Date: 2026-09-18
// Description: Read a feed into plain entries — headline, link, summary, enclosure, image, video flag
// Notes: Pure: bytes in, entries out, no network and no catalog. The store, the ticker (mg-feedr)
//        and the podcast player (mg-streamr) all read feeds through here, and tests need only
//        fixtures.
//        feed-rs puts an RSS <enclosure> and the iTunes tags into a media object, while Atom
//        carries enclosures as links with rel="enclosure". Both are read.
//        Identity fields (guid, first link, title, published) are taken exactly as the store
//        always took them, so items already in a catalog keep the same identity key.
//        Summaries arrive as HTML; they become plain text short enough for a one-line ticker

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use feed_rs::model::{Entry, MediaObject};
use feed_rs::parser;
use serde::Serialize;
use url::Url;

pub const SUMMARY_MAX_CHARS: usize = 400;
pub const TITLE_MAX_CHARS: usize = 300;
pub const UNTITLED: &str = "(untitled)";
// sites whose links are videos even without a video enclosure
const VIDEO_HOSTS: [&str; 5] = [
    "youtube.com",
    "youtu.be",
    "vimeo.com",
    "dailymotion.com",
    "twitch.tv",
];
const VIDEO_TYPE_PREFIX: &str = "video/";
const ENCLOSURE_REL: &str = "enclosure";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Enclosure {
    pub url: String,
    pub media_type: Option<String>,
    pub length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParsedEntry {
    pub guid: Option<String>,
    pub url: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub published: Option<DateTime<Utc>>,
    pub enclosure: Option<Enclosure>,
    pub image_url: Option<String>,
    pub duration_seconds: Option<u64>,
    pub has_video: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParsedFeed {
    pub title: Option<String>,
    pub image_url: Option<String>,
    pub entries: Vec<ParsedEntry>,
}

// Parse RSS, Atom or JSON Feed bytes into plain entries
pub fn parse_feed(bytes: &[u8]) -> Result<ParsedFeed> {
    let fixed = fix_minute_durations(bytes);
    let feed = parser::parse(fixed.as_ref()).context("parse RSS/Atom feed")?;
    // a channel's artwork: the podcast cover (iTunes image / logo), else its icon
    let image_url = feed
        .logo
        .as_ref()
        .or(feed.icon.as_ref())
        .map(|image| image.uri.clone())
        .filter(|uri| !uri.trim().is_empty());
    Ok(ParsedFeed {
        title: feed.title.map(|t| t.content),
        image_url,
        entries: feed.entries.into_iter().map(read_entry).collect(),
    })
}

// the tag whose value feed-rs misreads
const ITUNES_DURATION: &[u8] = b"<itunes:duration>";

// feed-rs knows "H:MM:SS" and plain seconds but not the common "MM:SS", so "30:00" came out as
// 30 seconds — and a player would call a 30-minute episode finished at once. Rewrite each
// "MM:SS" inside <itunes:duration> as "0:MM:SS" before parsing; nothing else is touched
fn fix_minute_durations(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let find = |haystack: &[u8], from: usize| {
        haystack[from..]
            .windows(ITUNES_DURATION.len())
            .position(|w| w == ITUNES_DURATION)
            .map(|p| from + p)
    };
    let Some(first) = find(bytes, 0) else {
        return std::borrow::Cow::Borrowed(bytes);
    };
    let mut out = Vec::with_capacity(bytes.len() + 64);
    let mut done = 0;
    let mut next = Some(first);
    while let Some(tag) = next {
        let value_start = tag + ITUNES_DURATION.len();
        let value_end = bytes[value_start..]
            .iter()
            .position(|b| *b == b'<')
            .map_or(bytes.len(), |p| value_start + p);
        let value = &bytes[value_start..value_end];
        out.extend_from_slice(&bytes[done..value_start]);
        // feed-rs wants exactly H:MM:SS, so write that out in full ("5:07" → "0:05:07",
        // "120:00" → "2:00:00") rather than just prefixing hours
        match minutes_seconds(value.trim_ascii()) {
            Some((minutes, seconds)) => out.extend_from_slice(
                format!("{}:{:02}:{seconds:02}", minutes / 60, minutes % 60).as_bytes(),
            ),
            None => out.extend_from_slice(value),
        }
        done = value_end;
        next = find(bytes, value_end);
    }
    out.extend_from_slice(&bytes[done..]);
    std::borrow::Cow::Owned(out)
}

// "30:00" or "5:07" → (minutes, seconds): 1–3 digits, a colon, exactly 2 digits; else None
fn minutes_seconds(text: &[u8]) -> Option<(u32, u32)> {
    let colon = text.iter().position(|b| *b == b':')?;
    let (minutes, seconds) = (&text[..colon], &text[colon + 1..]);
    if !(1..=3).contains(&minutes.len())
        || seconds.len() != 2
        || !minutes.iter().chain(seconds).all(u8::is_ascii_digit)
    {
        return None;
    }
    let number = |digits: &[u8]| std::str::from_utf8(digits).ok()?.parse::<u32>().ok();
    Some((number(minutes)?, number(seconds)?))
}

// One feed-rs entry → the fields the suite uses
fn read_entry(entry: Entry) -> ParsedEntry {
    let guid = nonempty(&entry.id);
    let url = entry.links.first().and_then(|l| nonempty(&l.href));
    let enclosure = enclosure_of(&entry);
    let media_types: Vec<String> = entry
        .media
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|c| c.content_type.as_ref().map(|t| t.to_string()))
        .collect();
    let has_video = is_video(
        enclosure.as_ref().and_then(|e| e.media_type.as_deref()),
        &media_types,
        url.as_deref(),
    );
    let summary = entry
        .summary
        .as_ref()
        .map(|s| plain_text(&s.content, SUMMARY_MAX_CHARS))
        .filter(|s| !s.is_empty());
    ParsedEntry {
        guid,
        url,
        title: entry
            .title
            .map(|t| t.content)
            .unwrap_or_else(|| UNTITLED.into()),
        summary,
        published: entry.published,
        image_url: image_of(&entry.media),
        duration_seconds: duration_of(&entry.media),
        enclosure,
        has_video,
    }
}

// The item's attached file: a media/enclosure element first, else an Atom enclosure link
fn enclosure_of(entry: &Entry) -> Option<Enclosure> {
    let from_media = entry
        .media
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|c| {
            Some(Enclosure {
                url: c.url.as_ref()?.to_string(),
                media_type: c.content_type.as_ref().map(|t| t.to_string()),
                length: c.size,
            })
        });
    from_media.or_else(|| {
        entry
            .links
            .iter()
            .find(|l| l.rel.as_deref() == Some(ENCLOSURE_REL))
            .map(|l| Enclosure {
                url: l.href.clone(),
                media_type: l.media_type.clone(),
                length: l.length,
            })
    })
}

// The item's own picture: the first thumbnail (media:thumbnail or itunes:image)
fn image_of(media: &[MediaObject]) -> Option<String> {
    media
        .iter()
        .flat_map(|m| m.thumbnails.iter())
        .map(|t| t.image.uri.clone())
        .find(|uri| !uri.trim().is_empty())
}

// How long the item plays, when the feed says (itunes:duration or media duration)
fn duration_of(media: &[MediaObject]) -> Option<u64> {
    media.iter().find_map(|m| {
        m.duration
            .or_else(|| m.content.iter().find_map(|c| c.duration))
            .map(|d| d.as_secs())
    })
}

// A video item: a video/* enclosure or media type, or a link on a known video site
pub fn is_video(enclosure_type: Option<&str>, media_types: &[String], link: Option<&str>) -> bool {
    let video_type = |t: &str| t.to_ascii_lowercase().starts_with(VIDEO_TYPE_PREFIX);
    enclosure_type.is_some_and(video_type)
        || media_types.iter().any(|t| video_type(t))
        || link.is_some_and(on_video_host)
}

// Is this link's host one of the video sites, or a subdomain of one
fn on_video_host(link: &str) -> bool {
    let Some(host) = Url::parse(link)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    else {
        return false;
    };
    VIDEO_HOSTS
        .iter()
        .any(|site| host == *site || host.ends_with(&format!(".{site}")))
}

// HTML → one line of plain text: tags dropped, common entities decoded, spaces collapsed, cut to `max` chars
pub fn plain_text(html: &str, max: usize) -> String {
    let mut text = String::with_capacity(html.len().min(max * 2));
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            // a tag boundary separates words ("<p>a</p><p>b</p>" → "a b")
            '>' if in_tag => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    let decoded = decode_entities(&text);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    let mut cut: String = collapsed.chars().take(max.saturating_sub(1)).collect();
    cut.push('\u{2026}');
    cut
}

// A headline for display: entities decoded, spaces collapsed, at most `TITLE_MAX_CHARS`
// no tag stripping — a plain RSS title may truly contain "<" once the XML is unescaped;
// only HTML-typed titles (The Verge's Atom) leave entities like "&#8217;" behind
pub fn title_text(raw: &str) -> String {
    let collapsed = decode_entities(raw)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.chars().count() <= TITLE_MAX_CHARS {
        return collapsed;
    }
    let mut cut: String = collapsed.chars().take(TITLE_MAX_CHARS - 1).collect();
    cut.push('\u{2026}');
    cut
}

// Decode the entities feeds actually use; anything unrecognised stays as written
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        // an entity is short and ends with ';' — look no further than 10 chars
        let end = after
            .char_indices()
            .take(10)
            .find(|(_, c)| *c == ';')
            .map(|(i, _)| i);
        let decoded = end.and_then(|end| entity(&after[1..end]).map(|c| (c, end)));
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// One entity name or number → its character
fn entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        "hellip" => Some('\u{2026}'),
        "mdash" => Some('\u{2014}'),
        "ndash" => Some('\u{2013}'),
        "rsquo" => Some('\u{2019}'),
        "lsquo" => Some('\u{2018}'),
        "rdquo" => Some('\u{201d}'),
        "ldquo" => Some('\u{201c}'),
        _ => {
            let number = name.strip_prefix('#')?;
            let code = match number.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => number.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

// A trimmed-nonempty string, owned
fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PODCAST: &str = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
<channel><title>Late Show</title><itunes:image href="https://cdn.example/cover.jpg"/>
<item><title>Episode 1</title><guid>ep-1</guid><link>https://example.com/ep1</link>
<description>&lt;p&gt;Hello &amp;amp; welcome&lt;/p&gt;&lt;p&gt;to the show&lt;/p&gt;</description>
<enclosure url="https://cdn.example/ep1.mp3" type="audio/mpeg" length="12345"/>
<itunes:image href="https://cdn.example/ep1.jpg"/><itunes:duration>01:02:03</itunes:duration>
<pubDate>Fri, 18 Sep 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"#;

    const ATOM_VIDEO: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Clips</title><id>urn:clips</id><updated>2026-09-18T00:00:00Z</updated>
<entry><title>Enclosed</title><id>urn:a</id><updated>2026-09-18T00:00:00Z</updated>
<link href="https://example.com/a"/><link rel="enclosure" href="https://cdn.example/a.mp4" type="video/mp4" length="99"/></entry>
<entry><title>Tube</title><id>urn:b</id><updated>2026-09-18T00:00:00Z</updated>
<link href="https://www.youtube.com/watch?v=abc"/></entry>
<entry><title>Plain</title><id>urn:c</id><updated>2026-09-18T00:00:00Z</updated>
<link href="https://notyoutube.com/x"/></entry>
</feed>"#;

    #[test]
    fn a_podcast_item_gives_its_enclosure_artwork_duration_and_plain_summary() {
        let feed = parse_feed(PODCAST.as_bytes()).expect("parses");
        assert_eq!(feed.title.as_deref(), Some("Late Show"));
        assert_eq!(
            feed.image_url.as_deref(),
            Some("https://cdn.example/cover.jpg")
        );
        let ep = &feed.entries[0];
        assert_eq!(ep.guid.as_deref(), Some("ep-1"));
        assert_eq!(ep.url.as_deref(), Some("https://example.com/ep1"));
        assert_eq!(
            ep.enclosure,
            Some(Enclosure {
                url: "https://cdn.example/ep1.mp3".into(),
                media_type: Some("audio/mpeg".into()),
                length: Some(12345)
            })
        );
        assert_eq!(ep.image_url.as_deref(), Some("https://cdn.example/ep1.jpg"));
        assert_eq!(ep.duration_seconds, Some(3723));
        assert_eq!(ep.summary.as_deref(), Some("Hello & welcome to the show"));
        assert!(!ep.has_video, "audio is not video");
        assert!(ep.published.is_some());
    }

    #[test]
    fn atom_enclosures_and_video_hosts_mark_video_but_lookalike_hosts_do_not() {
        let feed = parse_feed(ATOM_VIDEO.as_bytes()).expect("parses");
        let [enclosed, tube, plain] = &feed.entries[..] else {
            panic!("three entries")
        };
        assert!(enclosed.has_video);
        assert_eq!(
            enclosed.enclosure.as_ref().map(|e| e.url.as_str()),
            Some("https://cdn.example/a.mp4")
        );
        assert!(tube.has_video, "a YouTube link is a video");
        assert!(tube.enclosure.is_none());
        assert!(!plain.has_video, "notyoutube.com is not youtube.com");
    }

    #[test]
    fn plain_text_strips_tags_decodes_entities_and_cuts_long_text() {
        assert_eq!(
            plain_text("<b>Tom&nbsp;&amp;&#32;Jerry</b> &#x2014; &bogus; &", 100),
            "Tom & Jerry \u{2014} &bogus; &"
        );
        assert_eq!(plain_text("  a\n\n b  ", 100), "a b");
        let long = plain_text(&"word ".repeat(200), 20);
        assert_eq!(long.chars().count(), 20);
        assert!(long.ends_with('\u{2026}'));
        assert_eq!(
            plain_text("<script>x</script>", 10),
            "x",
            "only tags go; text inside stays"
        );
    }

    #[test]
    fn minute_second_durations_are_read_as_minutes() {
        let feed = |d: &str| {
            format!(
                r#"<?xml version="1.0"?><rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel><title>S</title><item><title>E</title><guid>g</guid><enclosure url="https://c.example/e.mp3" type="audio/mpeg" length="1"/><itunes:duration>{d}</itunes:duration></item></channel></rss>"#
            )
        };
        let seconds = |d: &str| parse_feed(feed(d).as_bytes()).unwrap().entries[0].duration_seconds;
        assert_eq!(
            seconds("30:00"),
            Some(1800),
            "MM:SS is minutes, not seconds"
        );
        assert_eq!(seconds(" 5:07 "), Some(307));
        assert_eq!(seconds("01:02:03"), Some(3723), "H:MM:SS unchanged");
        assert_eq!(seconds("1800"), Some(1800), "plain seconds unchanged");
        assert_eq!(seconds("120:00"), Some(7200), "over an hour of minutes");
        assert_eq!(minutes_seconds(b"90:00"), Some((90, 0)));
        assert_eq!(minutes_seconds(b"1:02:03"), None);
        assert_eq!(minutes_seconds(b"30:0"), None);
    }

    #[test]
    fn titles_decode_entities_but_keep_a_real_angle_bracket() {
        assert_eq!(title_text("doesn&#8217;t  stop"), "doesn\u{2019}t stop");
        assert_eq!(title_text("a < b &amp; c"), "a < b & c");
        assert_eq!(
            title_text(&"x".repeat(400)).chars().count(),
            TITLE_MAX_CHARS
        );
    }

    #[test]
    fn video_detection_reads_types_and_hosts() {
        assert!(is_video(Some("VIDEO/MP4"), &[], None));
        assert!(is_video(None, &["video/webm".into()], None));
        assert!(is_video(None, &[], Some("https://youtu.be/x")));
        assert!(is_video(None, &[], Some("https://m.youtube.com/watch?v=1")));
        assert!(!is_video(
            Some("audio/mpeg"),
            &["image/jpeg".into()],
            Some("https://example.com")
        ));
        assert!(!is_video(None, &[], Some("not a url")));
    }

    #[test]
    fn garbage_is_an_error_not_an_empty_feed() {
        assert!(parse_feed(b"<html>not a feed").is_err());
    }
}
