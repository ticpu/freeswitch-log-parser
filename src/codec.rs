//! Codec descriptors from `switch_core_media.c`'s negotiation trace.
//!
//! The audio and video forms carry different fields, so a token is only
//! meaningful together with the media type of the line it came from.

use std::fmt;

/// Which negotiation trace a codec token came from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecMedia {
    Audio,
    Video,
}

impl fmt::Display for CodecMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecMedia::Audio => f.pad("audio"),
            CodecMedia::Video => f.pad("video"),
        }
    }
}

/// One codec as FreeSWITCH spells it inside a negotiation trace's brackets.
///
/// Everything past the payload type is `None` for video, whose trace carries
/// only `name:payload_type`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecOffer {
    pub name: String,
    pub payload_type: u8,
    pub clock_rate: Option<u32>,
    pub ptime: Option<u32>,
    pub bitrate: Option<u32>,
    pub channels: Option<u8>,
}

impl fmt::Display for CodecOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.payload_type)?;
        if let Some(rate) = self.clock_rate {
            write!(f, " {rate}Hz")?;
        }
        if let Some(ptime) = self.ptime {
            write!(f, " {ptime}ms")?;
        }
        if let Some(bitrate) = self.bitrate {
            write!(f, " {bitrate}b")?;
        }
        if let Some(channels) = self.channels {
            write!(f, " {channels}ch")?;
        }
        Ok(())
    }
}

/// Why a codec token could not be read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecParseError {
    /// Field count matches no known form for this media type.
    Arity { media: CodecMedia, fields: usize },
    /// A numeric field was not a number.
    NotNumeric { field: &'static str },
    /// The codec name was empty.
    EmptyName,
}

impl fmt::Display for CodecParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecParseError::Arity { media, fields } => {
                write!(f, "{fields} fields is not a {media} codec token")
            }
            CodecParseError::NotNumeric { field } => write!(f, "non-numeric {field}"),
            CodecParseError::EmptyName => f.write_str("empty codec name"),
        }
    }
}

impl std::error::Error for CodecParseError {}

impl CodecOffer {
    /// Read a bracket-stripped token, e.g. `opus:116:16000:20:0:1` for audio or
    /// `H264:109` for video.
    ///
    /// The seven-field audio form is `switch_core_media.c:5575`'s only, which
    /// logs `actual_samples_per_second` after the rate where its siblings do
    /// not; that extra field is skipped so all audio forms yield the same shape.
    pub fn parse(media: CodecMedia, token: &str) -> Result<Self, CodecParseError> {
        let mut fields = token.split(':');
        let name = fields.next().unwrap_or_default();
        if name.is_empty() {
            return Err(CodecParseError::EmptyName);
        }
        let rest: Vec<&str> = fields.collect();

        let num = |raw: &str, field: &'static str| -> Result<u32, CodecParseError> {
            raw.parse()
                .map_err(|_| CodecParseError::NotNumeric { field })
        };
        let payload_type = |raw: &str| -> Result<u8, CodecParseError> {
            raw.parse().map_err(|_| CodecParseError::NotNumeric {
                field: "payload type",
            })
        };

        let arity = |fields: usize| CodecParseError::Arity { media, fields };

        match (media, rest.as_slice()) {
            (CodecMedia::Video, [pt]) => Ok(CodecOffer {
                name: name.to_string(),
                payload_type: payload_type(pt)?,
                clock_rate: None,
                ptime: None,
                bitrate: None,
                channels: None,
            }),
            (CodecMedia::Audio, [pt, rate, ptime, bitrate, channels])
            | (CodecMedia::Audio, [pt, rate, _, ptime, bitrate, channels]) => Ok(CodecOffer {
                name: name.to_string(),
                payload_type: payload_type(pt)?,
                clock_rate: Some(num(rate, "clock rate")?),
                ptime: Some(num(ptime, "ptime")?),
                bitrate: Some(num(bitrate, "bitrate")?),
                channels: Some(
                    num(channels, "channels")?
                        .try_into()
                        .map_err(|_| CodecParseError::NotNumeric { field: "channels" })?,
                ),
            }),
            _ => Err(arity(rest.len() + 1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audio(token: &str) -> CodecOffer {
        CodecOffer::parse(CodecMedia::Audio, token).expect("parsed")
    }

    #[test]
    fn audio_six_field_form() {
        let c = audio("opus:116:16000:20:0:1");
        assert_eq!(c.name, "opus");
        assert_eq!(c.payload_type, 116);
        assert_eq!(c.clock_rate, Some(16000));
        assert_eq!(c.ptime, Some(20));
        assert_eq!(c.bitrate, Some(0));
        assert_eq!(c.channels, Some(1));
    }

    #[test]
    fn audio_seven_field_form_skips_the_extra_rate() {
        // switch_core_media.c:5575 logs actual_samples_per_second after the
        // codec rate; every other audio trace omits it.
        let c = audio("PCMU:0:8000:8000:20:64000:1");
        assert_eq!(c.clock_rate, Some(8000));
        assert_eq!(c.ptime, Some(20));
        assert_eq!(c.bitrate, Some(64000));
        assert_eq!(c.channels, Some(1));
    }

    #[test]
    fn video_two_field_form() {
        let c = CodecOffer::parse(CodecMedia::Video, "H264:109").expect("parsed");
        assert_eq!(c.name, "H264");
        assert_eq!(c.payload_type, 109);
        assert_eq!(c.clock_rate, None);
        assert_eq!(c.channels, None);
    }

    #[test]
    fn media_type_decides_the_arity() {
        assert!(CodecOffer::parse(CodecMedia::Audio, "H264:109").is_err());
        assert!(CodecOffer::parse(CodecMedia::Video, "opus:116:16000:20:0:1").is_err());
    }

    #[test]
    fn malformed_tokens_do_not_parse_partially() {
        assert_eq!(
            CodecOffer::parse(CodecMedia::Audio, ""),
            Err(CodecParseError::EmptyName)
        );
        assert_eq!(
            CodecOffer::parse(CodecMedia::Video, "H264:notanumber"),
            Err(CodecParseError::NotNumeric {
                field: "payload type"
            })
        );
        assert_eq!(
            CodecOffer::parse(CodecMedia::Audio, "opus:116:sixteen:20:0:1"),
            Err(CodecParseError::NotNumeric {
                field: "clock rate"
            })
        );
        assert!(matches!(
            CodecOffer::parse(CodecMedia::Audio, "opus:116:16000"),
            Err(CodecParseError::Arity { fields: 3, .. })
        ));
    }

    #[test]
    fn display_omits_absent_fields() {
        assert_eq!(
            audio("opus:116:16000:20:0:1").to_string(),
            "opus:116 16000Hz 20ms 0b 1ch"
        );
        assert_eq!(
            CodecOffer::parse(CodecMedia::Video, "H264:109")
                .unwrap()
                .to_string(),
            "H264:109"
        );
    }
}
